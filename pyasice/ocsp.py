import hashlib
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Union

import requests
from asn1crypto import ocsp
from asn1crypto.algos import DigestInfo
from asn1crypto.core import Boolean, OctetString
from asn1crypto.ocsp import CertId, OCSPRequest, OCSPResponse, TBSRequest, TBSRequestExtension, TBSRequestExtensionId
from asn1crypto.x509 import Certificate as ASN1Certificate
from oscrypto import asymmetric

from . import signature_verifier
from .exceptions import PyAsiceError
from .tsa import default_get_session

# OID for OCSP Signing EKU (RFC 6960 Section 4.2.2.2)
OCSP_SIGNING_EKU_OID = "1.3.6.1.5.5.7.3.9"

# OCSP certificate status values (RFC 6960)
CERT_STATUS_GOOD = "good"
CERT_STATUS_REVOKED = "revoked"
CERT_STATUS_UNKNOWN = "unknown"


class SKHackedTBSRequestExtension(TBSRequestExtension):
    """A workaround class for compatibility with old java libraries used in SK.ee

    The jdigidoc library used in the SK service fails to validate an OCSP request
    made up with the original TBSRequestExtension because it expects a plain OctetString in the value field.
    This does not break validation with newer libraries including digidoc-tool
    """

    _fields = [
        ("extn_id", TBSRequestExtensionId),
        ("critical", Boolean, {"default": False}),
        ("extn_value", OctetString),  # This replaces ParsableOctetString
    ]


class OCSPError(PyAsiceError):
    pass


class OCSPCertificateRevokedError(OCSPError):
    """The certificate has been revoked."""

    pass


class OCSPCertificateUnknownError(OCSPError):
    """The certificate status is unknown to the OCSP responder."""

    pass


class OCSPResponseExpiredError(OCSPError):
    """The OCSP response has expired (nextUpdate is in the past)."""

    pass


class OCSPResponseNotYetValidError(OCSPError):
    """The OCSP response is not yet valid (thisUpdate is in the future)."""

    pass


class OCSPNonceMismatchError(OCSPError):
    """The nonce in the OCSP response does not match the request."""

    pass


class OCSPResponderCertificateError(OCSPError):
    """The OCSP responder certificate is invalid (missing EKU, etc.)."""

    pass


class OCSPCertIDMismatchError(OCSPError):
    """The CertID in the OCSP response does not match the request."""

    pass


class OCSP(object):
    """
    Certificate validation request via the OCSP protocol, using the asn1crypto/ocspbuilder stack.

    Perform certificate validation:

        ocsp = OCSP(ocsp_service_url)
        ocsp.validate(subject_cert, issuer_cert, signature)

    Check an arbitrary response:

        ocsp = OCSP.load(der_encoded_binary_data)
    """

    REQUEST_CONTENT_TYPE = "application/ocsp-request"
    RESPONSE_CONTENT_TYPE = "application/ocsp-response"

    # Default time tolerance for clock skew (5 minutes)
    DEFAULT_CLOCK_SKEW_SECONDS = 300
    # Default max age for thisUpdate (24 hours)
    DEFAULT_MAX_AGE_SECONDS = 86400

    def __init__(self, url=None, get_session=None, clock_skew_seconds=None, max_age_seconds=None):
        """
        :param url: OCSP responder URL
        :param get_session: Factory function for requests.Session
        :param clock_skew_seconds: Tolerance for clock differences (default 300 seconds)
        :param max_age_seconds: Maximum age for thisUpdate (default 86400 seconds/24h)
        """
        self.url = url
        self.ocsp_response: Optional[OCSPResponse] = None
        self._request_nonce: Optional[bytes] = None
        self._request_cert_id: Optional[CertId] = None

        self.clock_skew_seconds = clock_skew_seconds if clock_skew_seconds is not None else self.DEFAULT_CLOCK_SKEW_SECONDS
        self.max_age_seconds = max_age_seconds if max_age_seconds is not None else self.DEFAULT_MAX_AGE_SECONDS

        self.session = get_session() if get_session else default_get_session()

    def validate(self, subject_cert, issuer_cert, signature):
        """
        A correct OCSP request for BDOC-TM shall contain a DER-encoded "Hash value of the binary value of
        the signature along with hash algorithm identifier" in the `nonce` field. Yet at the moment, apparently
        the OCSP service doesn't qualify for time-mark BDOCs so this is probably not significant

        Provide certificates as asn1crypto.x509.Certificate object, oscrypto.asymmetric.Certificate object,
          a buffer (bytes) in PEM or DER format, or a path to a certificate file.

        :param issuer_cert: a certificate object, a buffer or a path to file
        :param subject_cert: a certificate object, a buffer or a path to file
        :param bytes signature: required for BDOC-TM format
        :return:
        """
        ocsp_request = self.build_ocsp_request(subject_cert, issuer_cert, signature)

        # Store request nonce for later verification (RFC 6960 replay protection)
        self._request_nonce = self._extract_nonce_from_request(ocsp_request)

        # Store request certID for later verification
        self._request_cert_id = ocsp_request["tbs_request"]["request_list"][0]["req_cert"]

        req = requests.Request(
            method="post",
            url=self.url,
            data=ocsp_request.dump(),
            headers={"Content-Type": self.REQUEST_CONTENT_TYPE, "Connection": "close"},
        )

        try:
            response = self.session.send(req.prepare())
            response.raise_for_status()
        except requests.ConnectionError:
            raise OCSPError(f"Failed to connect to OCSP service at {self.url}")
        except requests.HTTPError as e:
            raise OCSPError(f"Bad response from OCSP service at {self.url}: {e}")

        content_type = response.headers["Content-Type"]
        if content_type != self.RESPONSE_CONTENT_TYPE:
            raise OCSPError(f"Invalid response content type '{content_type}' returned by OCSP service at {self.url}")

        ocsp_response = OCSPResponse.load(response.content)
        self.verify_response(
            ocsp_response,
            expected_nonce=self._request_nonce,
            expected_cert_id=self._request_cert_id,
            clock_skew_seconds=self.clock_skew_seconds,
            max_age_seconds=self.max_age_seconds,
        )

        self.ocsp_response = ocsp_response
        return self

    @staticmethod
    def _extract_nonce_from_request(ocsp_request: OCSPRequest) -> Optional[bytes]:
        """Extract the nonce value from an OCSP request."""
        extensions = ocsp_request["tbs_request"]["request_extensions"]
        if extensions:
            for ext in extensions:
                if ext["extn_id"].native == "nonce":
                    return ext["extn_value"].native
        return None

    def get_responder_certs(self) -> Tuple[ASN1Certificate]:
        """Get OCSP responder certificates embedded in the response"""
        return tuple(self.ocsp_response.basic_ocsp_response["certs"])

    def get_encapsulated_response(self):
        """Get a DER-encoded OCSP response"""
        return self.ocsp_response.dump()

    def verify(self):
        self.verify_response(
            self.ocsp_response,
            expected_nonce=self._request_nonce,
            expected_cert_id=self._request_cert_id,
            clock_skew_seconds=self.clock_skew_seconds,
            max_age_seconds=self.max_age_seconds,
        )

    @staticmethod
    def verify_response(
        ocsp_response: Union[OCSPResponse, bytes],
        expected_nonce: Optional[bytes] = None,
        expected_cert_id: Optional[CertId] = None,
        clock_skew_seconds: int = 300,
        max_age_seconds: int = 86400,
    ):
        """
        Verify the OCSP response per RFC 6960.

        Performs the following checks:
        1. Response status is "successful"
        2. Certificate status (good/revoked/unknown)
        3. thisUpdate/nextUpdate timestamp validation (Section 4.2.2.1)
        4. Nonce verification for replay protection
        5. Responder certificate EKU validation (Section 4.2.2.2)
        6. CertID match verification
        7. Signature verification

        :param ocsp_response: The OCSP response to verify
        :param expected_nonce: Nonce from the request (for replay protection)
        :param expected_cert_id: CertID from the request (for response matching)
        :param clock_skew_seconds: Tolerance for clock differences (default 300 seconds)
        :param max_age_seconds: Maximum age for thisUpdate (default 86400 seconds/24h)
        """
        if not isinstance(ocsp_response, OCSPResponse):
            ocsp_response = OCSPResponse.load(ocsp_response)

        ocsp_status = ocsp_response["response_status"].native
        if ocsp_status != "successful":
            raise OCSPError("OCSP validation failed: certificate is %s" % ocsp_status)

        basic_response: ocsp.BasicOCSPResponse = ocsp_response.basic_ocsp_response

        # Check cert_status (the actual certificate validity)
        single_response = ocsp_response.response_data["responses"][0]
        cert_status = single_response["cert_status"]
        status_name = cert_status.name

        if status_name == CERT_STATUS_GOOD:
            pass  # Certificate is valid, continue to signature verification
        elif status_name == CERT_STATUS_REVOKED:
            revoked_info = cert_status.chosen
            revocation_time = revoked_info["revocation_time"].native
            raise OCSPCertificateRevokedError(f"Certificate was revoked at {revocation_time}")
        elif status_name == CERT_STATUS_UNKNOWN:
            raise OCSPCertificateUnknownError("Certificate status is unknown to the OCSP responder")
        else:
            raise OCSPError(f"Unexpected certificate status: {status_name}")

        # RFC 6960 Section 4.2.2.1: thisUpdate/nextUpdate validation
        OCSP._verify_response_timestamps(single_response, clock_skew_seconds, max_age_seconds)

        # Verify nonce if one was sent in the request (replay protection)
        if expected_nonce is not None:
            OCSP._verify_nonce(basic_response, expected_nonce)

        # Verify CertID match if provided
        if expected_cert_id is not None:
            OCSP._verify_cert_id_match(single_response, expected_cert_id)

        # Signer's certificate
        certs = basic_response["certs"]
        cert: ASN1Certificate = certs[0]
        cert_bytes = cert.dump()

        # RFC 6960 Section 4.2.2.2: Verify responder certificate has OCSP Signing EKU
        OCSP._verify_responder_eku(cert)

        # the signed data, as ASN.1-encoded structure
        tbs_response: ocsp.ResponseData = ocsp_response.response_data
        tbs_bytes = tbs_response.dump()

        # the signature, as ASN.1-encoded structure
        signature: ocsp.OctetBitString = basic_response["signature"]

        # the signature algorithm, in form of "{HASH_ALGO}_{CRYPTO_ALGO}"
        # as per https://tools.ietf.org/html/rfc6960#section-4.3,
        # clients should support sha256_rsa and sha1_rsa, as well as sha1_dsa but that's unlikely to be used.
        signature_algorithm = basic_response["signature_algorithm"]["algorithm"].native
        if signature_algorithm not in ["sha256_rsa", "sha1_rsa"]:
            raise ValueError("Unsupported signature algorithm")

        signature_verifier.verify(cert_bytes, signature.native, tbs_bytes, hash_algo=signature_algorithm.split("_")[0])

    @staticmethod
    def _verify_response_timestamps(single_response, clock_skew_seconds: int, max_age_seconds: int):
        """
        Verify thisUpdate and nextUpdate per RFC 6960 Section 4.2.2.1.

        - thisUpdate MUST be sufficiently recent (within max_age_seconds)
        - thisUpdate MUST NOT be in the future (with clock_skew tolerance)
        - nextUpdate (if present) MUST be greater than current time
        """
        now = datetime.now(timezone.utc)

        this_update = single_response["this_update"].native
        if this_update.tzinfo is None:
            this_update = this_update.replace(tzinfo=timezone.utc)

        # Check thisUpdate is not in the future (with clock skew tolerance)
        from datetime import timedelta

        if this_update > now + timedelta(seconds=clock_skew_seconds):
            raise OCSPResponseNotYetValidError(
                f"OCSP response thisUpdate ({this_update}) is in the future"
            )

        # Check thisUpdate is not too old (max_age check)
        if (now - this_update).total_seconds() > max_age_seconds:
            raise OCSPResponseExpiredError(
                f"OCSP response thisUpdate ({this_update}) is too old (max age: {max_age_seconds}s)"
            )

        # Check nextUpdate if present
        next_update = single_response["next_update"].native
        if next_update is not None:
            if next_update.tzinfo is None:
                next_update = next_update.replace(tzinfo=timezone.utc)

            # nextUpdate must be greater than current time (with clock skew tolerance)
            if next_update < now - timedelta(seconds=clock_skew_seconds):
                raise OCSPResponseExpiredError(
                    f"OCSP response has expired (nextUpdate: {next_update})"
                )

    @staticmethod
    def _verify_nonce(basic_response: ocsp.BasicOCSPResponse, expected_nonce: bytes):
        """
        Verify the nonce in the response matches the request.

        Per RFC 6960 Section 4.4.1, if the client sent a nonce, the server
        SHOULD include it in the response for replay protection.
        """
        response_extensions = basic_response["tbs_response_data"]["response_extensions"]
        response_nonce = None

        if response_extensions:
            for ext in response_extensions:
                if ext["extn_id"].native == "nonce":
                    response_nonce = ext["extn_value"].native
                    break

        if response_nonce is None:
            raise OCSPNonceMismatchError("OCSP response does not contain a nonce (replay protection failed)")

        if response_nonce != expected_nonce:
            raise OCSPNonceMismatchError("OCSP response nonce does not match request nonce")

    @staticmethod
    def _verify_responder_eku(cert: ASN1Certificate):
        """
        Verify the OCSP responder certificate has id-kp-OCSPSigning EKU.

        Per RFC 6960 Section 4.2.2.2, a delegated responder certificate MUST
        contain the id-kp-OCSPSigning (1.3.6.1.5.5.7.3.9) extended key usage.
        """
        try:
            eku_ext = cert.extended_key_usage_value
            if eku_ext is None:
                raise OCSPResponderCertificateError(
                    "OCSP responder certificate does not have Extended Key Usage extension"
                )

            eku_oids = [eku.dotted for eku in eku_ext]
            if OCSP_SIGNING_EKU_OID not in eku_oids:
                raise OCSPResponderCertificateError(
                    f"OCSP responder certificate does not have id-kp-OCSPSigning EKU ({OCSP_SIGNING_EKU_OID})"
                )
        except Exception as e:
            if isinstance(e, OCSPResponderCertificateError):
                raise
            raise OCSPResponderCertificateError(f"Failed to verify OCSP responder EKU: {e}")

    @staticmethod
    def _verify_cert_id_match(single_response, expected_cert_id: CertId):
        """
        Verify the CertID in the response matches the request.

        This ensures the response is actually for the certificate we asked about.
        """
        response_cert_id = single_response["cert_id"]

        # Compare issuerNameHash
        if response_cert_id["issuer_name_hash"].native != expected_cert_id["issuer_name_hash"].native:
            raise OCSPCertIDMismatchError("OCSP response issuerNameHash does not match request")

        # Compare issuerKeyHash
        if response_cert_id["issuer_key_hash"].native != expected_cert_id["issuer_key_hash"].native:
            raise OCSPCertIDMismatchError("OCSP response issuerKeyHash does not match request")

        # Compare serialNumber
        if response_cert_id["serial_number"].native != expected_cert_id["serial_number"].native:
            raise OCSPCertIDMismatchError("OCSP response serialNumber does not match request")

    @classmethod
    def load(cls, binary_data, max_age_seconds=None):
        """
        Load an OCSP response from binary data.

        :param binary_data: DER-encoded OCSP response
        :param max_age_seconds: Override max_age for archived/historical responses
        """
        me = cls()
        me.ocsp_response = OCSPResponse.load(binary_data)
        if max_age_seconds is not None:
            me.max_age_seconds = max_age_seconds
        return me

    @classmethod
    def build_ocsp_request(
        cls,
        subject_cert: Union[asymmetric.Certificate, ASN1Certificate, bytes],
        issuer_cert: Union[asymmetric.Certificate, ASN1Certificate, bytes],
        signature=None,
    ) -> OCSPRequest:
        if not isinstance(issuer_cert, asymmetric.Certificate):
            issuer_cert = asymmetric.load_certificate(issuer_cert)
        if not isinstance(subject_cert, asymmetric.Certificate):
            subject_cert = asymmetric.load_certificate(subject_cert)

        extensions = None
        if signature is not None:
            nonce = cls.build_nonce(signature)
            extensions = [
                SKHackedTBSRequestExtension(
                    {
                        "extn_id": "nonce",
                        "critical": False,
                        "extn_value": nonce.dump(),
                    }
                )
            ]

        tbs_request = cls.build_tbs_request(subject_cert.asn1, issuer_cert.asn1, tbs_request_extensions=extensions)
        ocsp_request = OCSPRequest(
            {
                "tbs_request": tbs_request,
                "optional_signature": None,
            }
        )
        return ocsp_request

    @classmethod
    def build_nonce(cls, signature):
        digest = hashlib.sha256(signature).digest()
        obj = DigestInfo(
            {
                "digest_algorithm": {
                    "algorithm": "sha256",
                },
                "digest": digest,
            }
        )
        return obj

    @classmethod
    def build_tbs_request(
        cls,
        subject_cert: ASN1Certificate,
        issuer_cert: ASN1Certificate,
        tbs_request_extensions: Optional[List[TBSRequestExtension]] = None,
        request_extensions: Optional[list] = None,
        _key_hash_algo="sha1",
    ):
        """Build a TBSRequest entry for OCSPRequest"""
        return TBSRequest(
            {
                "request_list": [
                    {
                        "req_cert": {
                            "hash_algorithm": {"algorithm": _key_hash_algo},
                            "issuer_name_hash": getattr(subject_cert.issuer, _key_hash_algo),
                            "issuer_key_hash": getattr(issuer_cert.public_key, _key_hash_algo),
                            "serial_number": subject_cert.serial_number,
                        },
                        "single_request_extensions": request_extensions,
                    }
                ],
                "request_extensions": tbs_request_extensions,
            }
        )
