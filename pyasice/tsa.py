import hashlib
import os

import requests
from asn1crypto.cms import ContentInfo  # noqa
from asn1crypto.core import Integer, OctetString, SetOf
from asn1crypto.tsp import TimeStampReq, TimeStampResp

from .exceptions import PyAsiceError
from .signature_verifier import verify

# OID for Time Stamping EKU (RFC 3161)
TIME_STAMPING_EKU_OID = "1.3.6.1.5.5.7.3.8"


class TSAError(PyAsiceError):
    pass


class TSANonceMismatchError(TSAError):
    """The nonce in the TSA response does not match the request."""

    pass


class TSACertificateError(TSAError):
    """The TSA certificate is invalid (missing EKU, ESSCertID mismatch, etc.)."""

    pass


class TSAMissingCertificateError(TSAError):
    """The TSA response does not contain the required certificate."""

    pass


def default_get_session():
    return requests.Session()


class TSA:
    """
    Query a Time Stamping Authority (TSA) for a signature time stamp
    """

    REQUEST_CONTENT_TYPE = "application/timestamp-query"
    RESPONSE_CONTENT_TYPE = "application/timestamp-reply"

    # Default nonce size in bytes (64 bits recommended minimum per RFC 3161)
    DEFAULT_NONCE_SIZE = 8

    def __init__(self, url=None, get_session=None, nonce_size=None, policy_oid=None):
        """
        :param url: TSA service URL
        :param get_session: Factory function for requests.Session
        :param nonce_size: Size of nonce in bytes (default 8)
        :param policy_oid: Optional TSA policy OID to request
        """
        self.url = url
        self.ts_response = None
        self._request_nonce: int = None
        self.nonce_size = nonce_size if nonce_size is not None else self.DEFAULT_NONCE_SIZE
        self.policy_oid = policy_oid

        self.session = get_session() if get_session else default_get_session()

    def get_timestamp(self, message: bytes) -> ContentInfo:
        """Get the time stamp structure for embedding in a XAdES signature

        How to prepare the message:
        https://www.etsi.org/deliver/etsi_ts/101900_101999/101903/01.04.02_60/ts_101903v010402p.pdf
        section 7.3
        """
        # Generate and store nonce for replay protection (RFC 3161 Section 2.4.1)
        self._request_nonce = self._generate_nonce(self.nonce_size)

        request = self.build_ts_request(message, nonce=self._request_nonce, policy_oid=self.policy_oid)

        req = requests.Request(
            method="post",
            url=self.url,
            data=request.dump(),
            headers={
                "Content-Type": self.REQUEST_CONTENT_TYPE,
                "Connection": "close",
            },
        )

        try:
            response = self.session.send(req.prepare())
            response.raise_for_status()
        except requests.ConnectionError as e:
            raise TSAError("Failed to connect to TSA service at {}".format(self.url)) from e
        except requests.HTTPError as e:
            raise TSAError("Bad response from TSA service at {}: {}".format(self.url, e)) from e

        content_type = response.headers["Content-Type"]
        if content_type != self.RESPONSE_CONTENT_TYPE:
            raise TSAError(f"Invalid response content type '{content_type}' returned by TSA service at {self.url}")

        ts_response = TimeStampResp.load(response.content)
        # see asn1crypto.tsp.PKIStatus
        status = ts_response["status"]["status"].native
        if status != "granted":
            raise TSAError(f"Timestamping service denied the request with a status of {status}")

        # Verify nonce in response matches request (RFC 3161 Section 2.4.2)
        self._verify_response_nonce(ts_response, self._request_nonce)

        self.ts_response = ts_response
        return ts_response["time_stamp_token"]

    @staticmethod
    def _generate_nonce(size: int = 8) -> int:
        """Generate a cryptographically random nonce as an integer."""
        return int.from_bytes(os.urandom(size), byteorder="big")

    @staticmethod
    def _verify_response_nonce(ts_response: TimeStampResp, expected_nonce: int):
        """
        Verify the nonce in the TSA response matches the request.

        Per RFC 3161 Section 2.4.2, if a nonce is included in the request,
        the same nonce MUST be present in the response.
        """
        tst_info = ts_response["time_stamp_token"]["content"]["encap_content_info"]["content"].native
        response_nonce = tst_info.get("nonce")

        if response_nonce is None:
            raise TSANonceMismatchError("TSA response does not contain a nonce (replay protection failed)")

        if response_nonce != expected_nonce:
            raise TSANonceMismatchError(
                f"TSA response nonce ({response_nonce}) does not match request nonce ({expected_nonce})"
            )

    @classmethod
    def verify(cls, ts_response: bytes, original_message: bytes, expected_nonce: int = None):
        """
        Verify that the signature in the response is valid per RFC 3161.

        Performs the following checks:
        1. Response content type is signed_data
        2. Message imprint matches original message
        3. Message digest in signed attributes matches
        4. TSA certificate is present (cert_req=True)
        5. TSA certificate has id-kp-timeStamping EKU
        6. ESSCertID/ESSCertIDv2 validation (RFC 5816)
        7. Nonce verification (if provided)
        8. Signature verification

        https://tools.ietf.org/html/rfc5652#section-5.4

        :param ts_response: The timestamp response bytes
        :param original_message: The original message that was timestamped
        :param expected_nonce: Optional nonce to verify (for replay protection)
        """
        try:
            # any error during data structure parsing means the TS response is not valid
            ts_response = ContentInfo.load(ts_response)
            ts_content_type = ts_response.native["content_type"]

            # see asn1crypto.cms.ContentType
            if ts_content_type != "signed_data":
                raise ValueError(f"The TS response has invalid content type '{ts_content_type}'")

            content = ts_response["content"]

            # Get the encapsulated TS message ("econtent")
            econtent = content["encap_content_info"]["content"]

            # verify that the response refers to the original message

            message_imprint = econtent.native["message_imprint"]
            original_imprint = cls.build_message_imprint(original_message)
            if (
                message_imprint["hash_algorithm"]["algorithm"] != original_imprint["hash_algorithm"]["algorithm"]
                or message_imprint["hashed_message"] != original_imprint["hashed_message"]
            ):
                raise ValueError("The timestamped message differs from the original one")

            # Verify nonce if provided (RFC 3161 Section 2.4.2)
            if expected_nonce is not None:
                tst_info = econtent.native
                response_nonce = tst_info.get("nonce")
                if response_nonce is None:
                    raise TSANonceMismatchError("TSA response does not contain a nonce")
                if response_nonce != expected_nonce:
                    raise TSANonceMismatchError(
                        f"TSA response nonce ({response_nonce}) does not match expected nonce ({expected_nonce})"
                    )

            # Verify that "econtent" hash matches the message_digest attribute of signed_attrs

            digest_algo = content["digest_algorithms"][0]["algorithm"].native
            econtent_digest = getattr(hashlib, digest_algo)(econtent.contents).digest()

            signer_info = content["signer_infos"][0]

            signed_attrs = signer_info["signed_attrs"]

            md = [a for a in signed_attrs.native if a["type"] == "message_digest"][0]
            the_hash = md["values"][0]
            if econtent_digest != the_hash:
                raise ValueError("Message digests do not match")

            # Verify TSA certificate is present (we requested cert_req=True)
            certificates = content["certificates"]
            if certificates is None or len(certificates) == 0:
                raise TSAMissingCertificateError("TSA response does not contain a certificate (cert_req was True)")

            cert = certificates[0].chosen

            # RFC 3161: Verify TSA certificate has id-kp-timeStamping EKU
            cls._verify_tsa_eku(cert)

            # RFC 5816: Verify ESSCertID or ESSCertIDv2 matches the TSA certificate
            cls._verify_ess_cert_id(signed_attrs, cert)

            # Verify the signature with the included cert

            # To get signed data, we need some magic, as quoted from the RFC 5652 (the link in docstring):
            #    the DER encoding of the EXPLICIT SET OF tag, rather than of the IMPLICIT [0]
            #    tag, MUST be included in the message digest calculation
            # i.e. replace the current (class, tag) pair of the struct with those of the SET-OF type
            signed_attrs.implicit = False
            signed_attrs.class_ = SetOf.class_
            signed_attrs.tag = SetOf.tag
            signed_data = signed_attrs.dump(True)

            signature: OctetString = signer_info["signature"]
            signature_bytes = signature.native

            sig_algo = signer_info["signature_algorithm"]["algorithm"].native
            sig_hash_algo = sig_algo.split("_")[0]

            verify(cert.dump(), signature_bytes, signed_data, sig_hash_algo)

        except (TSANonceMismatchError, TSACertificateError, TSAMissingCertificateError):
            raise
        except Exception as e:
            raise TSAError("Invalid TSA response format") from e
        return ts_response

    @staticmethod
    def _verify_tsa_eku(cert):
        """
        Verify the TSA certificate has id-kp-timeStamping EKU.

        Per RFC 3161, the TSA certificate MUST have the id-kp-timeStamping
        (1.3.6.1.5.5.7.3.8) extended key usage.
        """
        try:
            eku_ext = cert.extended_key_usage_value
            if eku_ext is None:
                raise TSACertificateError(
                    "TSA certificate does not have Extended Key Usage extension"
                )

            eku_oids = [eku.dotted for eku in eku_ext]
            if TIME_STAMPING_EKU_OID not in eku_oids:
                raise TSACertificateError(
                    f"TSA certificate does not have id-kp-timeStamping EKU ({TIME_STAMPING_EKU_OID})"
                )
        except TSACertificateError:
            raise
        except Exception as e:
            raise TSACertificateError(f"Failed to verify TSA certificate EKU: {e}")

    @staticmethod
    def _verify_ess_cert_id(signed_attrs, cert):
        """
        Verify ESSCertID or ESSCertIDv2 matches the TSA certificate.

        Per RFC 5816, the signed attributes MUST contain either signing_certificate
        or signing_certificate_v2 attribute that identifies the TSA certificate.
        """
        # Look for signing_certificate_v2 (preferred) or signing_certificate
        ess_cert_id_v2 = None
        ess_cert_id = None

        for attr in signed_attrs:
            attr_type = attr["type"].native
            if attr_type == "signing_certificate_v2":
                ess_cert_id_v2 = attr["values"][0]
                break
            elif attr_type == "signing_certificate":
                ess_cert_id = attr["values"][0]

        if ess_cert_id_v2 is not None:
            # RFC 5035/5816: ESSCertIDv2 uses SHA-256 by default
            TSA._verify_ess_cert_id_v2(ess_cert_id_v2, cert)
        elif ess_cert_id is not None:
            # RFC 2634: ESSCertID uses SHA-1
            TSA._verify_ess_cert_id_v1(ess_cert_id, cert)
        else:
            raise TSACertificateError(
                "TSA response does not contain signing_certificate or signing_certificate_v2 attribute"
            )

    @staticmethod
    def _verify_ess_cert_id_v1(ess_cert_id, cert):
        """Verify ESSCertID (RFC 2634) matches the certificate using SHA-1."""
        try:
            certs = ess_cert_id["certs"]
            if len(certs) == 0:
                raise TSACertificateError("ESSCertID contains no certificate references")

            cert_id = certs[0]
            cert_hash = cert_id["cert_hash"].native

            # ESSCertID uses SHA-1
            actual_hash = hashlib.sha1(cert.dump()).digest()
            if cert_hash != actual_hash:
                raise TSACertificateError("ESSCertID hash does not match TSA certificate")
        except TSACertificateError:
            raise
        except Exception as e:
            raise TSACertificateError(f"Failed to verify ESSCertID: {e}")

    @staticmethod
    def _verify_ess_cert_id_v2(ess_cert_id_v2, cert):
        """Verify ESSCertIDv2 (RFC 5035/5816) matches the certificate."""
        try:
            certs = ess_cert_id_v2["certs"]
            if len(certs) == 0:
                raise TSACertificateError("ESSCertIDv2 contains no certificate references")

            cert_id = certs[0]
            cert_hash = cert_id["cert_hash"].native

            # Get hash algorithm (defaults to SHA-256)
            hash_algo = cert_id["hash_algorithm"]
            if hash_algo is not None:
                algo_name = hash_algo["algorithm"].native
            else:
                algo_name = "sha256"

            # Calculate actual certificate hash
            hash_func = getattr(hashlib, algo_name, None)
            if hash_func is None:
                raise TSACertificateError(f"Unsupported hash algorithm in ESSCertIDv2: {algo_name}")

            actual_hash = hash_func(cert.dump()).digest()
            if cert_hash != actual_hash:
                raise TSACertificateError("ESSCertIDv2 hash does not match TSA certificate")
        except TSACertificateError:
            raise
        except Exception as e:
            raise TSACertificateError(f"Failed to verify ESSCertIDv2: {e}")

    @staticmethod
    def build_message_imprint(message):
        if not isinstance(message, bytes):
            raise TypeError(f"Invalid message type: expected bytes, got {type(message)}")
        if not message:
            raise ValueError("Message can not be empty")

        return {
            "hash_algorithm": {"algorithm": "sha256"},
            "hashed_message": hashlib.sha256(message).digest(),
        }

    @classmethod
    def build_ts_request(cls, message, nonce: int = None, policy_oid: str = None):
        """
        Build a timestamp request per RFC 3161.

        :param message: The message to timestamp
        :param nonce: Optional nonce for replay protection (RFC 3161 Section 2.4.1)
        :param policy_oid: Optional TSA policy OID
        """
        req_dict = {
            "version": "v1",
            "message_imprint": cls.build_message_imprint(message),
            "cert_req": True,  # Need the TSA cert in the response for validation
        }

        if nonce is not None:
            req_dict["nonce"] = Integer(nonce)

        if policy_oid is not None:
            req_dict["req_policy"] = policy_oid

        return TimeStampReq(req_dict)

    def dump(self) -> bytes:
        return self.ts_response.dump()

    @classmethod
    def load(cls, binary_data):
        me = cls()
        me.ts_response = ContentInfo.load(binary_data)
        return me
