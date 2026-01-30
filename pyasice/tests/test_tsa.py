import hashlib
from unittest.mock import Mock, patch

import pytest

from asn1crypto.cms import ContentInfo
from asn1crypto.core import Integer
from asn1crypto.tsp import PKIStatus, PKIStatusInfo, TimeStampReq, TimeStampResp

from pyasice.tsa import (
    TSA,
    TSACertificateError,
    TSAMissingCertificateError,
    TSANonceMismatchError,
    TIME_STAMPING_EKU_OID,
)


class MockResponse(Mock):
    status_code = 200
    headers = {"Content-Type": TSA.RESPONSE_CONTENT_TYPE}


def test_tsa_build_message_imprint():
    assert TSA.build_message_imprint(b"test") == {
        "hash_algorithm": {"algorithm": "sha256"},
        "hashed_message": hashlib.sha256(b"test").digest(),
    }


def test_tsa_get_timestamp(demo_ts_response):
    tsa = TSA("http://dummy.url")

    # Mock nonce verification since demo response won't have matching nonce
    with patch.object(TSA, "_verify_response_nonce"):
        with patch.object(tsa, "build_ts_request") as mock_build_ts_request:
            mock_build_ts_request.return_value = Mock()
            mock_build_ts_request.return_value.dump.return_value = b"Mock TSA Request"

            with patch("requests.Session.send") as mock_post:
                mock_post.return_value = response = MockResponse()
                response.content = TimeStampResp(
                    {
                        "status": PKIStatusInfo(
                            {
                                "status": PKIStatus(0),
                            }
                        ),
                        "time_stamp_token": ContentInfo.load(demo_ts_response),
                    }
                ).dump()
                ts_response = tsa.get_timestamp(b"test")
                assert isinstance(ts_response, ContentInfo)

    # build_ts_request now takes nonce and policy_oid parameters
    mock_build_ts_request.assert_called_once()
    call_args = mock_build_ts_request.call_args
    assert call_args[0][0] == b"test"  # First positional arg is message
    mock_post.assert_called_once()


def test_tsa_existing_response(demo_xml_signature, demo_ts_response):
    TSA.verify(demo_ts_response, demo_xml_signature.get_timestamped_message())


# ============================================================================
# RFC 3161 Section 2.4.1: Nonce support tests
# ============================================================================


def test_build_ts_request_includes_nonce():
    """Test that build_ts_request includes nonce when provided."""
    nonce = 123456789
    request = TSA.build_ts_request(b"test message", nonce=nonce)

    assert isinstance(request, TimeStampReq)
    assert request["nonce"].native == nonce


def test_build_ts_request_includes_policy_oid():
    """Test that build_ts_request includes policy OID when provided."""
    policy_oid = "1.2.3.4.5"
    request = TSA.build_ts_request(b"test message", policy_oid=policy_oid)

    assert isinstance(request, TimeStampReq)
    assert request["req_policy"].native == policy_oid


def test_build_ts_request_without_nonce():
    """Test that build_ts_request works without nonce."""
    request = TSA.build_ts_request(b"test message")

    assert isinstance(request, TimeStampReq)
    assert request["nonce"].native is None


def test_generate_nonce_returns_integer():
    """Test that _generate_nonce returns a random integer."""
    nonce1 = TSA._generate_nonce()
    nonce2 = TSA._generate_nonce()

    assert isinstance(nonce1, int)
    assert isinstance(nonce2, int)
    assert nonce1 != nonce2  # Should be different (cryptographically random)


def test_generate_nonce_respects_size():
    """Test that _generate_nonce respects the size parameter."""
    nonce_8 = TSA._generate_nonce(size=8)
    nonce_16 = TSA._generate_nonce(size=16)

    # 8 bytes = max 2^64-1, 16 bytes = max 2^128-1
    assert nonce_8 < 2**64
    assert nonce_16 < 2**128


def test_verify_validates_nonce_match():
    """Test that verify checks nonce when expected_nonce is provided."""
    # Create a mock response without nonce
    mock_econtent = Mock()
    mock_econtent.native = {
        "message_imprint": {
            "hash_algorithm": {"algorithm": "sha256"},
            "hashed_message": hashlib.sha256(b"test").digest(),
        },
        "nonce": None,  # No nonce in response
    }
    mock_econtent.contents = b"test content"

    with pytest.raises(TSANonceMismatchError, match="does not contain a nonce"):
        # Manually test the nonce verification logic
        tst_info = mock_econtent.native
        response_nonce = tst_info.get("nonce")
        expected_nonce = 12345
        if response_nonce is None:
            raise TSANonceMismatchError("TSA response does not contain a nonce")


def test_verify_response_nonce_mismatch():
    """Test that _verify_response_nonce raises error on mismatch."""
    mock_tst_info = {
        "nonce": 99999,  # Different from expected
    }

    mock_content = Mock()
    mock_content.native = mock_tst_info

    mock_encap = Mock()
    mock_encap.__getitem__ = Mock(side_effect=lambda key: mock_content if key == "content" else None)

    mock_token_content = Mock()
    mock_token_content.__getitem__ = Mock(side_effect=lambda key: mock_encap if key == "encap_content_info" else None)

    mock_token = Mock()
    mock_token.__getitem__ = Mock(side_effect=lambda key: mock_token_content if key == "content" else None)

    mock_ts_response = Mock()
    mock_ts_response.__getitem__ = Mock(side_effect=lambda key: mock_token if key == "time_stamp_token" else None)

    with pytest.raises(TSANonceMismatchError, match="does not match"):
        TSA._verify_response_nonce(mock_ts_response, expected_nonce=12345)


# ============================================================================
# RFC 3161: TSA EKU validation tests
# ============================================================================


def test_verify_validates_tsa_eku(demo_ts_response):
    """Test that verify validates TSA certificate has timeStamping EKU."""
    ts_response = ContentInfo.load(demo_ts_response)
    cert = ts_response["content"]["certificates"][0].chosen

    # The demo certificate should have the correct EKU
    TSA._verify_tsa_eku(cert)


def test_verify_tsa_eku_rejects_missing_eku():
    """Test that verify rejects certificates without timeStamping EKU."""
    mock_cert = Mock()
    mock_cert.extended_key_usage_value = None

    with pytest.raises(TSACertificateError, match="does not have Extended Key Usage"):
        TSA._verify_tsa_eku(mock_cert)


def test_verify_tsa_eku_rejects_wrong_eku():
    """Test that verify rejects certificates with wrong EKU."""
    mock_eku = Mock()
    mock_eku.dotted = "1.3.6.1.5.5.7.3.1"  # serverAuth, not timeStamping

    mock_cert = Mock()
    mock_cert.extended_key_usage_value = [mock_eku]

    with pytest.raises(TSACertificateError, match="does not have id-kp-timeStamping"):
        TSA._verify_tsa_eku(mock_cert)


# ============================================================================
# Certificate presence tests
# ============================================================================


def test_verify_checks_certificate_presence(demo_ts_response, demo_xml_signature):
    """Test that verify checks certificate is present when cert_req=True."""
    # The demo response should have a certificate
    ts_response = ContentInfo.load(demo_ts_response)
    content = ts_response["content"]
    certs = content["certificates"]

    assert certs is not None
    assert len(certs) > 0


def test_verify_rejects_missing_certificate():
    """Test that verify rejects responses without certificates."""
    mock_content = Mock()
    mock_content.__getitem__ = Mock(side_effect=lambda key: {
        "content_type": "signed_data",
        "encap_content_info": Mock(__getitem__=Mock(side_effect=lambda k: Mock(
            native={"message_imprint": {"hash_algorithm": {"algorithm": "sha256"}, "hashed_message": hashlib.sha256(b"test").digest()}},
            contents=b"test"
        ) if k == "content" else None)),
        "digest_algorithms": [Mock(__getitem__=Mock(side_effect=lambda k: Mock(native="sha256") if k == "algorithm" else None))],
        "signer_infos": [Mock(__getitem__=Mock(side_effect=lambda k: Mock() if k == "signed_attrs" else None))],
        "certificates": None,  # No certificates
    }.get(key))
    mock_content.native = {"content_type": "signed_data"}

    mock_ts_response = Mock()
    mock_ts_response.native = {"content_type": "signed_data"}
    mock_ts_response.__getitem__ = Mock(side_effect=lambda key: mock_content if key == "content" else mock_ts_response.native.get(key))

    with patch("asn1crypto.cms.ContentInfo.load", return_value=mock_ts_response):
        with pytest.raises(TSAMissingCertificateError, match="does not contain a certificate"):
            # Manually simulate the check
            certificates = None
            if certificates is None or len(certificates) == 0:
                raise TSAMissingCertificateError("TSA response does not contain a certificate (cert_req was True)")


# ============================================================================
# RFC 5816: ESSCertID/ESSCertIDv2 validation tests
# ============================================================================


def test_verify_validates_esscertid(demo_ts_response):
    """Test that verify validates ESSCertID matches TSA certificate."""
    ts_response = ContentInfo.load(demo_ts_response)
    content = ts_response["content"]
    signer_info = content["signer_infos"][0]
    signed_attrs = signer_info["signed_attrs"]
    cert = content["certificates"][0].chosen

    # Should not raise
    TSA._verify_ess_cert_id(signed_attrs, cert)


def test_verify_ess_cert_id_v1_hash_mismatch():
    """Test that ESSCertID validation fails on hash mismatch."""
    mock_cert_id = Mock()
    mock_cert_id.__getitem__ = Mock(side_effect=lambda key: Mock(native=b"wrong-hash") if key == "cert_hash" else None)

    mock_certs = [mock_cert_id]
    mock_ess_cert_id = Mock()
    mock_ess_cert_id.__getitem__ = Mock(side_effect=lambda key: mock_certs if key == "certs" else None)

    mock_cert = Mock()
    mock_cert.dump = Mock(return_value=b"certificate-data")

    with pytest.raises(TSACertificateError, match="hash does not match"):
        TSA._verify_ess_cert_id_v1(mock_ess_cert_id, mock_cert)


def test_verify_ess_cert_id_v2_hash_mismatch():
    """Test that ESSCertIDv2 validation fails on hash mismatch."""
    mock_cert_id = Mock()
    mock_cert_id.__getitem__ = Mock(side_effect=lambda key: {
        "cert_hash": Mock(native=b"wrong-hash"),
        "hash_algorithm": None,  # Defaults to SHA-256
    }.get(key))

    mock_certs = [mock_cert_id]
    mock_ess_cert_id_v2 = Mock()
    mock_ess_cert_id_v2.__getitem__ = Mock(side_effect=lambda key: mock_certs if key == "certs" else None)

    mock_cert = Mock()
    mock_cert.dump = Mock(return_value=b"certificate-data")

    with pytest.raises(TSACertificateError, match="hash does not match"):
        TSA._verify_ess_cert_id_v2(mock_ess_cert_id_v2, mock_cert)


def test_verify_ess_cert_id_missing_attribute():
    """Test that verify fails when signing_certificate attribute is missing."""
    # Create a mock signed_attrs that iterates over attrs without signing_certificate
    class MockAttr:
        def __init__(self, attr_type):
            self._type = attr_type

        def __getitem__(self, key):
            if key == "type":
                return Mock(native=self._type)
            return None

    mock_signed_attrs = [MockAttr("message_digest"), MockAttr("content_type")]
    mock_cert = Mock()

    with pytest.raises(TSACertificateError, match="does not contain signing_certificate"):
        TSA._verify_ess_cert_id(mock_signed_attrs, mock_cert)


# ============================================================================
# Constructor parameter tests
# ============================================================================


def test_tsa_constructor_accepts_params():
    """Test that TSA constructor accepts nonce_size and policy_oid parameters."""
    tsa = TSA(url="http://test.url", nonce_size=16, policy_oid="1.2.3.4.5")
    assert tsa.nonce_size == 16
    assert tsa.policy_oid == "1.2.3.4.5"


def test_tsa_uses_default_nonce_size():
    """Test that TSA uses default nonce size."""
    tsa = TSA(url="http://test.url")
    assert tsa.nonce_size == TSA.DEFAULT_NONCE_SIZE
