from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

import pytest

from asn1crypto.ocsp import OCSPRequest, OCSPResponse
from asn1crypto.x509 import Certificate as ASN1Certificate
from cryptography.hazmat.primitives.serialization import Encoding
from oscrypto.asymmetric import load_certificate

from pyasice.ocsp import (
    OCSP,
    OCSPCertIDMismatchError,
    OCSPCertificateRevokedError,
    OCSPCertificateUnknownError,
    OCSPNonceMismatchError,
    OCSPResponderCertificateError,
    OCSPResponseExpiredError,
    OCSPResponseNotYetValidError,
)

from .conftest import cert_builder


class MockResponse(Mock):
    status_code = 200
    headers = {"Content-Type": OCSP.RESPONSE_CONTENT_TYPE}


@pytest.mark.parametrize("signature", [None, b"some-signature-bytes"])
def test_ocsp_build_request(private_key_rsa, certificate_rsa, signature):
    issuer_cert = cert_builder(private_key_rsa, subject="issuer CA", issuer="CA").public_bytes(Encoding.DER)
    subject_cert = certificate_rsa.public_bytes(Encoding.DER)
    resp = OCSP.build_ocsp_request(subject_cert, issuer_cert, signature=signature)
    assert isinstance(resp, OCSPRequest)

    issuer_cert = load_certificate(issuer_cert)
    subject_cert = load_certificate(subject_cert)
    resp = OCSP.build_ocsp_request(subject_cert, issuer_cert, signature=signature)
    assert isinstance(resp, OCSPRequest)

    issuer_cert = issuer_cert.asn1
    subject_cert = subject_cert.asn1
    resp = OCSP.build_ocsp_request(subject_cert, issuer_cert, signature=signature)
    assert isinstance(resp, OCSPRequest)


def test_ocsp_existing_response(demo_ocsp_response):
    # Use large max_age for archived/demo responses
    ocsp_resp = OCSP.load(demo_ocsp_response, max_age_seconds=10 * 365 * 24 * 3600)
    assert isinstance(ocsp_resp, OCSP)

    certs = ocsp_resp.get_responder_certs()
    assert len(certs) > 0
    assert isinstance(certs[0], ASN1Certificate)

    assert certs[0].subject.native["common_name"] == "TEST of SK OCSP RESPONDER 2011"
    assert certs[0].issuer.native["common_name"] == "TEST of EE Certification Centre Root CA"

    OCSP.verify_response(ocsp_resp.get_encapsulated_response(), max_age_seconds=10 * 365 * 24 * 3600)
    ocsp_resp.verify()


def test_ocsp_validate(demo_ocsp_response):
    # Use large max_age for archived demo response
    ocsp = OCSP("http://dummy.url", max_age_seconds=10 * 365 * 24 * 3600)

    # Get the real cert_id from the demo response to use in our mock request
    real_response = OCSPResponse.load(demo_ocsp_response)
    real_cert_id = real_response.response_data["responses"][0]["cert_id"]

    # Create a proper nested mock for OCSPRequest structure using real cert_id
    mock_request_item = Mock()
    mock_request_item.__getitem__ = Mock(side_effect=lambda key: real_cert_id if key == "req_cert" else None)

    # Create mock for tbs_request
    mock_tbs_request = Mock()
    mock_tbs_request.__getitem__ = Mock(side_effect=lambda key: {
        "request_list": [mock_request_item],
        "request_extensions": None,  # No nonce in this test
    }.get(key))

    mock_ocsp_request = Mock()
    mock_ocsp_request.__getitem__ = Mock(side_effect=lambda key: mock_tbs_request if key == "tbs_request" else None)
    mock_ocsp_request.dump.return_value = b"Mock OCSP Request"

    with patch.object(ocsp, "build_ocsp_request") as mock_build_ocsp_request:
        mock_build_ocsp_request.return_value = mock_ocsp_request

        with patch("requests.Session.send") as mock_post:
            mock_post.return_value = response = MockResponse()
            response.content = demo_ocsp_response
            ocsp.validate(b"subject cert", b"issuer cert", b"some-signature")

    mock_build_ocsp_request.assert_called_once_with(b"subject cert", b"issuer cert", b"some-signature")
    mock_post.assert_called_once()


def test_verify_response_rejects_revoked_status(demo_ocsp_response):
    ocsp_response = OCSPResponse.load(demo_ocsp_response)
    real_response_data = ocsp_response.response_data

    mock_cert_status = Mock()
    mock_cert_status.name = "revoked"
    mock_revoked_info = Mock()
    mock_revoked_info.__getitem__ = Mock(
        side_effect=lambda key: Mock(native=datetime(2024, 1, 15, 12, 0, 0)) if key == "revocation_time" else None
    )
    mock_cert_status.chosen = mock_revoked_info

    mock_single_response = Mock()
    mock_single_response.__getitem__ = Mock(side_effect=lambda key: mock_cert_status if key == "cert_status" else None)

    mock_response_data = Mock()
    mock_response_data.__getitem__ = Mock(side_effect=lambda key: [mock_single_response] if key == "responses" else None)
    mock_response_data.dump = real_response_data.dump

    with patch.object(OCSPResponse, "response_data", new_callable=lambda: property(lambda self: mock_response_data)):
        with pytest.raises(OCSPCertificateRevokedError, match="Certificate was revoked at"):
            OCSP.verify_response(ocsp_response)


def test_verify_response_rejects_unknown_status(demo_ocsp_response):
    ocsp_response = OCSPResponse.load(demo_ocsp_response)
    real_response_data = ocsp_response.response_data

    mock_cert_status = Mock()
    mock_cert_status.name = "unknown"

    mock_single_response = Mock()
    mock_single_response.__getitem__ = Mock(side_effect=lambda key: mock_cert_status if key == "cert_status" else None)

    mock_response_data = Mock()
    mock_response_data.__getitem__ = Mock(side_effect=lambda key: [mock_single_response] if key == "responses" else None)
    mock_response_data.dump = real_response_data.dump

    with patch.object(OCSPResponse, "response_data", new_callable=lambda: property(lambda self: mock_response_data)):
        with pytest.raises(OCSPCertificateUnknownError, match="Certificate status is unknown"):
            OCSP.verify_response(ocsp_response)


def test_verify_response_accepts_good_status(demo_ocsp_response):
    # The demo_ocsp_response has a 'good' status
    # Note: We skip timestamp validation for archived responses by using a large max_age
    OCSP.verify_response(demo_ocsp_response, max_age_seconds=10 * 365 * 24 * 3600)


# ============================================================================
# RFC 6960 Section 4.2.2.1: thisUpdate/nextUpdate validation tests
# ============================================================================


def test_verify_response_checks_thisUpdate_freshness():
    """Test that _verify_response_timestamps rejects stale thisUpdate."""
    old_time = datetime(2020, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    mock_single_response = Mock()
    mock_single_response.__getitem__ = Mock(side_effect=lambda key: {
        "this_update": Mock(native=old_time),
        "next_update": Mock(native=datetime.now(timezone.utc) + timedelta(hours=24)),
    }.get(key))

    with pytest.raises(OCSPResponseExpiredError, match="thisUpdate.*too old"):
        OCSP._verify_response_timestamps(mock_single_response, clock_skew_seconds=300, max_age_seconds=3600)


def test_verify_response_checks_nextUpdate_expiry():
    """Test that _verify_response_timestamps rejects expired nextUpdate."""
    current_time = datetime.now(timezone.utc) - timedelta(minutes=5)
    expired_time = datetime.now(timezone.utc) - timedelta(hours=1)

    mock_single_response = Mock()
    mock_single_response.__getitem__ = Mock(side_effect=lambda key: {
        "this_update": Mock(native=current_time),
        "next_update": Mock(native=expired_time),
    }.get(key))

    with pytest.raises(OCSPResponseExpiredError, match="has expired"):
        OCSP._verify_response_timestamps(mock_single_response, clock_skew_seconds=300, max_age_seconds=3600)


def test_verify_response_rejects_future_thisUpdate():
    """Test that _verify_response_timestamps rejects future thisUpdate."""
    future_time = datetime.now(timezone.utc) + timedelta(hours=1)

    mock_single_response = Mock()
    mock_single_response.__getitem__ = Mock(side_effect=lambda key: {
        "this_update": Mock(native=future_time),
        "next_update": Mock(native=future_time + timedelta(hours=24)),
    }.get(key))

    with pytest.raises(OCSPResponseNotYetValidError, match="in the future"):
        OCSP._verify_response_timestamps(mock_single_response, clock_skew_seconds=60, max_age_seconds=3600)


def test_verify_response_timestamps_accepts_valid_response():
    """Test that _verify_response_timestamps accepts valid timestamps."""
    current_time = datetime.now(timezone.utc) - timedelta(minutes=5)
    next_update_time = datetime.now(timezone.utc) + timedelta(hours=24)

    mock_single_response = Mock()
    mock_single_response.__getitem__ = Mock(side_effect=lambda key: {
        "this_update": Mock(native=current_time),
        "next_update": Mock(native=next_update_time),
    }.get(key))

    # Should not raise
    OCSP._verify_response_timestamps(mock_single_response, clock_skew_seconds=300, max_age_seconds=3600)


def test_verify_response_timestamps_handles_no_nextUpdate():
    """Test that _verify_response_timestamps handles missing nextUpdate."""
    current_time = datetime.now(timezone.utc) - timedelta(minutes=5)

    mock_single_response = Mock()
    mock_single_response.__getitem__ = Mock(side_effect=lambda key: {
        "this_update": Mock(native=current_time),
        "next_update": Mock(native=None),  # No nextUpdate
    }.get(key))

    # Should not raise
    OCSP._verify_response_timestamps(mock_single_response, clock_skew_seconds=300, max_age_seconds=3600)


# ============================================================================
# Nonce verification tests (replay protection)
# ============================================================================


def test_validate_verifies_nonce_match(demo_ocsp_response):
    """Test that validate verifies nonce matches between request and response."""
    ocsp_response = OCSPResponse.load(demo_ocsp_response)
    basic_response = ocsp_response.basic_ocsp_response

    # The demo response may not have a nonce, so we test the verification logic directly
    expected_nonce = b"test-nonce-12345"

    # Test case 1: Response without nonce when one is expected
    with patch.object(OCSP, "_verify_nonce") as mock_verify:
        mock_verify.side_effect = OCSPNonceMismatchError("OCSP response does not contain a nonce")
        with pytest.raises(OCSPNonceMismatchError, match="does not contain a nonce"):
            OCSP.verify_response(ocsp_response, expected_nonce=expected_nonce, max_age_seconds=10 * 365 * 24 * 3600)


def test_nonce_mismatch_raises_error():
    """Test that mismatched nonces raise OCSPNonceMismatchError."""
    # Create a mock basic response with a different nonce
    mock_extension = Mock()
    mock_extension.__getitem__ = Mock(side_effect=lambda key: {
        "extn_id": Mock(native="nonce"),
        "extn_value": Mock(native=b"different-nonce"),
    }.get(key))

    mock_extensions = [mock_extension]
    mock_tbs_response_data = Mock()
    mock_tbs_response_data.__getitem__ = Mock(side_effect=lambda key: mock_extensions if key == "response_extensions" else None)

    mock_basic_response = Mock()
    mock_basic_response.__getitem__ = Mock(side_effect=lambda key: mock_tbs_response_data if key == "tbs_response_data" else None)

    with pytest.raises(OCSPNonceMismatchError, match="does not match"):
        OCSP._verify_nonce(mock_basic_response, b"expected-nonce")


# ============================================================================
# Responder EKU validation tests (RFC 6960 Section 4.2.2.2)
# ============================================================================


def test_verify_response_validates_responder_eku(demo_ocsp_response):
    """Test that verify_response validates OCSP responder has OCSPSigning EKU."""
    ocsp_response = OCSPResponse.load(demo_ocsp_response)
    basic_response = ocsp_response.basic_ocsp_response
    cert = basic_response["certs"][0]

    # The demo certificate should have the correct EKU
    # This test verifies the check runs without error
    OCSP._verify_responder_eku(cert)


def test_verify_responder_eku_rejects_missing_eku():
    """Test that verify rejects certificates without OCSP Signing EKU."""
    mock_cert = Mock()
    mock_cert.extended_key_usage_value = None

    with pytest.raises(OCSPResponderCertificateError, match="does not have Extended Key Usage"):
        OCSP._verify_responder_eku(mock_cert)


def test_verify_responder_eku_rejects_wrong_eku():
    """Test that verify rejects certificates with wrong EKU."""
    mock_eku = Mock()
    mock_eku.dotted = "1.3.6.1.5.5.7.3.1"  # serverAuth, not OCSPSigning

    mock_cert = Mock()
    mock_cert.extended_key_usage_value = [mock_eku]

    with pytest.raises(OCSPResponderCertificateError, match="does not have id-kp-OCSPSigning"):
        OCSP._verify_responder_eku(mock_cert)


# ============================================================================
# CertID match verification tests
# ============================================================================


def test_verify_response_checks_certid_match(demo_ocsp_response):
    """Test that verify_response checks CertID matches between request and response."""
    ocsp_response = OCSPResponse.load(demo_ocsp_response)
    single_response = ocsp_response.response_data["responses"][0]
    response_cert_id = single_response["cert_id"]

    # Verify matching CertID passes
    OCSP._verify_cert_id_match(single_response, response_cert_id)


def test_certid_mismatch_issuer_name_hash():
    """Test that mismatched issuerNameHash raises OCSPCertIDMismatchError."""
    mock_response_cert_id = Mock()
    mock_response_cert_id.__getitem__ = Mock(side_effect=lambda key: {
        "issuer_name_hash": Mock(native=b"response-hash"),
        "issuer_key_hash": Mock(native=b"key-hash"),
        "serial_number": Mock(native=12345),
    }.get(key))

    mock_expected_cert_id = Mock()
    mock_expected_cert_id.__getitem__ = Mock(side_effect=lambda key: {
        "issuer_name_hash": Mock(native=b"different-hash"),
        "issuer_key_hash": Mock(native=b"key-hash"),
        "serial_number": Mock(native=12345),
    }.get(key))

    mock_single_response = Mock()
    mock_single_response.__getitem__ = Mock(side_effect=lambda key: mock_response_cert_id if key == "cert_id" else None)

    with pytest.raises(OCSPCertIDMismatchError, match="issuerNameHash"):
        OCSP._verify_cert_id_match(mock_single_response, mock_expected_cert_id)


def test_certid_mismatch_serial_number():
    """Test that mismatched serialNumber raises OCSPCertIDMismatchError."""
    mock_response_cert_id = Mock()
    mock_response_cert_id.__getitem__ = Mock(side_effect=lambda key: {
        "issuer_name_hash": Mock(native=b"name-hash"),
        "issuer_key_hash": Mock(native=b"key-hash"),
        "serial_number": Mock(native=12345),
    }.get(key))

    mock_expected_cert_id = Mock()
    mock_expected_cert_id.__getitem__ = Mock(side_effect=lambda key: {
        "issuer_name_hash": Mock(native=b"name-hash"),
        "issuer_key_hash": Mock(native=b"key-hash"),
        "serial_number": Mock(native=99999),  # Different serial
    }.get(key))

    mock_single_response = Mock()
    mock_single_response.__getitem__ = Mock(side_effect=lambda key: mock_response_cert_id if key == "cert_id" else None)

    with pytest.raises(OCSPCertIDMismatchError, match="serialNumber"):
        OCSP._verify_cert_id_match(mock_single_response, mock_expected_cert_id)


# ============================================================================
# Clock skew tolerance tests
# ============================================================================


def test_ocsp_constructor_accepts_tolerance_params():
    """Test that OCSP constructor accepts clock_skew and max_age parameters."""
    ocsp = OCSP(url="http://test.url", clock_skew_seconds=120, max_age_seconds=7200)
    assert ocsp.clock_skew_seconds == 120
    assert ocsp.max_age_seconds == 7200


def test_ocsp_uses_default_tolerances():
    """Test that OCSP uses default tolerance values."""
    ocsp = OCSP(url="http://test.url")
    assert ocsp.clock_skew_seconds == OCSP.DEFAULT_CLOCK_SKEW_SECONDS
    assert ocsp.max_age_seconds == OCSP.DEFAULT_MAX_AGE_SECONDS
