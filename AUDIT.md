# Security Audit Report: pyasice Signing Library

**Audit Date:** January 2026
**Library Version:** 1.2.0
**Auditor:** Security Analysis
**Classification:** Comprehensive Security Review

---

## Executive Summary

This document presents a comprehensive security audit of the `pyasice` library, a Python implementation for creating, reading, and verifying XAdES/XMLDsig/eIDAS electronic signatures and ASiC-E (BDOC 2.1) containers.

### Overall Assessment

| Category | Rating | Notes |
|----------|--------|-------|
| **Cryptographic Implementation** | GOOD | Uses well-established libraries (cryptography, oscrypto) |
| **Standards Compliance** | GOOD | Compliant with BDOC 2.1.2, XAdES, ASiC-E standards |
| **XML Security** | NEEDS ATTENTION | Several XML security hardening opportunities |
| **Protocol Implementation** | GOOD | OCSP (RFC 6960) and TSA (RFC 3161) correctly implemented |
| **Certificate Validation** | NEEDS ATTENTION | Missing certificate chain validation |
| **Input Validation** | NEEDS ATTENTION | Some input validation gaps |
| **Error Handling** | ACCEPTABLE | Could expose sensitive information in some cases |

### Qualified Digital Signature Compliance

For **legally binding qualified digital signatures** under eIDAS Regulation (EU) No 910/2014:

| Requirement | Status | Details |
|-------------|--------|---------|
| XAdES Baseline Profile | PARTIAL | Supports XAdES-BES, XAdES-T, XAdES-LT profiles |
| Time-stamping (RFC 3161) | COMPLIANT | Properly implemented |
| OCSP Validation (RFC 6960) | COMPLIANT | Properly implemented |
| Certificate Chain Validation | NOT IMPLEMENTED | Critical gap |
| Qualified Certificate Verification | NOT IMPLEMENTED | Must be done externally |
| Long-term Preservation (XAdES-LTA) | NOT IMPLEMENTED | No archive timestamps |

---

## Table of Contents

1. [Scope and Methodology](#1-scope-and-methodology)
2. [Standards Compliance Analysis](#2-standards-compliance-analysis)
3. [Security Findings](#3-security-findings)
4. [Cryptographic Analysis](#4-cryptographic-analysis)
5. [XML Security Analysis](#5-xml-security-analysis)
6. [Protocol Implementation Review](#6-protocol-implementation-review)
7. [Container Security](#7-container-security)
8. [Test Coverage Analysis](#8-test-coverage-analysis)
9. [Recommendations](#9-recommendations)
10. [Compliance Checklist](#10-compliance-checklist)

---

## 1. Scope and Methodology

### 1.1 Files Reviewed

| File | Lines | Purpose |
|------|-------|---------|
| `xmlsig.py` | 561 | XAdES XML signature structure |
| `container.py` | 389 | ASiC-E/BDOC container handling |
| `ocsp.py` | 229 | OCSP protocol implementation |
| `tsa.py` | 173 | TimeStamping Authority client |
| `signature_verifier.py` | 76 | Cryptographic signature verification |
| `utils.py` | 39 | Signature finalization utilities |
| `exceptions.py` | 22 | Custom exception hierarchy |
| `templates/signature.xml` | 93 | XAdES signature template |
| `templates/manifest.xml` | 5 | ASiC-E manifest template |
| **Test files** | 702 | Test coverage |

### 1.2 Standards Referenced

- **ETSI TS 101 903 v1.4.2** - XML Advanced Electronic Signatures (XAdES)
- **ETSI TS 103 171** - XAdES Baseline Profile
- **ETSI TS 102 918 v1.2.1** - Associated Signature Containers (ASiC)
- **ETSI TS 103 174** - ASiC Baseline Profile
- **RFC 3161** - Internet X.509 PKI Time-Stamp Protocol (TSP)
- **RFC 6960** - X.509 Internet PKI Online Certificate Status Protocol (OCSP)
- **RFC 5652** - Cryptographic Message Syntax (CMS)
- **W3C XML Signature Syntax and Processing** (XMLDsig)
- **W3C Exclusive XML Canonicalization** (Exclusive C14N)
- **BDOC 2.1.2 Specification** (Estonian digital signature standard)
- **eIDAS Regulation (EU) No 910/2014**

---

## 2. Standards Compliance Analysis

### 2.1 XAdES Compliance (ETSI TS 101 903)

#### 2.1.1 Supported Profiles

| Profile | Support | Location |
|---------|---------|----------|
| **XAdES-BES** (Basic Electronic Signature) | YES | `xmlsig.py` |
| **XAdES-EPES** (Explicit Policy) | YES | `templates/signature.xml:43-58` |
| **XAdES-T** (Timestamp) | YES | `xmlsig.py:440-456` |
| **XAdES-C** (Complete) | PARTIAL | OCSP embedded, but no complete refs |
| **XAdES-X** (Extended) | NO | Not implemented |
| **XAdES-XL** (Extended Long-term) | PARTIAL | Via OCSP/TSA embedding |
| **XAdES-A** (Archival) | NO | No archive timestamps |

#### 2.1.2 Required Elements Analysis

```
SignedProperties (MANDATORY)
├── SignedSignatureProperties (MANDATORY)
│   ├── SigningTime                    ✓ Implemented (xmlsig.py:232-236)
│   ├── SigningCertificate             ✓ Implemented (xmlsig.py:163-164)
│   └── SignaturePolicyIdentifier      ✓ Implemented (template:43-58)
└── SignedDataObjectProperties
    └── DataObjectFormat               ✓ Implemented (xmlsig.py:224-225)
```

#### 2.1.3 Compliance Issues

| Issue | Severity | Reference | Details |
|-------|----------|-----------|---------|
| No SigningCertificateV2 support | LOW | ETSI EN 319 132-1 | Uses legacy SigningCertificate element |
| No CommitmentTypeIndication | LOW | XAdES 7.2.6 | Optional but recommended for legal validity |
| No SignerRole | LOW | XAdES 7.2.8 | Optional element not supported |
| Hardcoded BDOC policy OID | MEDIUM | template:46 | `urn:oid:1.3.6.1.4.1.10015.1000.3.2.1` is Estonian-specific |

### 2.2 ASiC-E Compliance (ETSI TS 102 918)

#### 2.2.1 Container Structure

```
container.asice (ZIP)
├── mimetype                           ✓ First entry, uncompressed (container.py:323-325)
├── META-INF/
│   ├── manifest.xml                   ✓ Implemented (container.py:306-317)
│   └── signatures*.xml                ✓ Implemented (container.py:217-231)
└── [data files]                       ✓ Implemented (container.py:149-166)
```

#### 2.2.2 Compliance Issues

| Issue | Severity | Reference | Details |
|-------|----------|-----------|---------|
| mimetype verification is strict | LOW | ETSI TS 102 918 6.2.1 | mimetype is optional per spec but enforced |
| No ASiC-S support | INFO | ETSI TS 102 918 | Only ASiC-E supported |

### 2.3 RFC 3161 (TSP) Compliance

| Requirement | Status | Location |
|-------------|--------|----------|
| TimeStampReq structure | COMPLIANT | `tsa.py:157-164` |
| MessageImprint with SHA-256 | COMPLIANT | `tsa.py:144-154` |
| Version v1 | COMPLIANT | `tsa.py:159` |
| certReq = TRUE | COMPLIANT | `tsa.py:162` |
| Response validation | COMPLIANT | `tsa.py:75-142` |

### 2.4 RFC 6960 (OCSP) Compliance

| Requirement | Status | Location |
|-------------|--------|----------|
| OCSPRequest structure | COMPLIANT | `ocsp.py:157-189` |
| Nonce extension | COMPLIANT | `ocsp.py:170-180` |
| Response status check | COMPLIANT | `ocsp.py:124-126` |
| Signature verification | COMPLIANT | `ocsp.py:149` |

**Note:** The library uses SHA-1 for issuer key hash in OCSP requests (`ocsp.py:211: _key_hash_algo="sha1"`), which is required for compatibility but SHA-1 is considered weak. This is acceptable as it's used for identification, not security.

---

## 3. Security Findings

### 3.1 Critical Findings

#### FINDING-001: No Certificate Chain Validation
- **Severity:** CRITICAL
- **Location:** Throughout codebase
- **Description:** The library does not validate certificate chains to a trusted root CA. It only verifies that signatures are mathematically correct against the provided certificate.
- **Impact:** Signatures from revoked, expired, or untrusted certificates will be accepted.
- **RFC Reference:** RFC 5280 Section 6 (Certification Path Validation)
- **Recommendation:** Implement full certificate path validation including:
  - Chain building to trusted root
  - Validity period checking
  - Key usage verification
  - Basic constraints validation

#### FINDING-002: No Certificate Revocation Checking During Verification
- **Severity:** CRITICAL
- **Location:** `signature_verifier.py`, `xmlsig.py:265-271`
- **Description:** When verifying existing signatures, the library does not check if the signing certificate was revoked at the time of signing.
- **Impact:** Signatures made with compromised certificates may be accepted.
- **Recommendation:** Check embedded OCSP response validity during verification, or query OCSP if not embedded.

### 3.2 High Severity Findings

#### FINDING-003: XML External Entity (XXE) Partial Mitigation
- **Severity:** HIGH
- **Location:** `xmlsig.py:93`
- **Code:**
  ```python
  parser = etree.XMLParser(remove_blank_text=False, remove_comments=True)
  ```
- **Description:** The XML parser does not explicitly disable external entity resolution. While lxml's default behavior is relatively safe, explicit hardening is recommended.
- **Impact:** Potential for XXE attacks when parsing malicious XML signatures.
- **Recommendation:** Add explicit XXE protection:
  ```python
  parser = etree.XMLParser(
      remove_blank_text=False,
      remove_comments=True,
      resolve_entities=False,
      no_network=True,
      dtd_validation=False,
      load_dtd=False
  )
  ```

#### FINDING-004: Missing Reference Validation (XSW Attack Surface)
- **Severity:** HIGH
- **Location:** `xmlsig.py`
- **Description:** The library does not validate that:
  1. All Reference URIs point to existing elements
  2. The SignedProperties Reference URI matches the actual SignedProperties Id
  3. No additional unsigned content exists that could be confused with signed content
- **Impact:** Potential for XML Signature Wrapping (XSW) attacks.
- **Reference:** "On Breaking SAML: Be Whoever You Want to Be" (Somorovsky et al.)
- **Recommendation:** Implement strict Reference validation before accepting signatures.

#### FINDING-005: OCSP Responder Certificate Not Validated
- **Severity:** HIGH
- **Location:** `ocsp.py:130-133`
- **Code:**
  ```python
  certs = basic_response["certs"]
  cert: ASN1Certificate = certs[0]
  ```
- **Description:** The OCSP responder's certificate is extracted and used for signature verification, but there's no validation that:
  1. The responder cert is authorized to sign OCSP responses (OCSPSigning EKU)
  2. The responder cert chains to a trusted CA
  3. The responder cert is issued by the same CA as the certificate being checked
- **Impact:** Malicious OCSP responses could be accepted.
- **RFC Reference:** RFC 6960 Section 4.2.2.2
- **Recommendation:** Validate OCSP responder authorization.

### 3.3 Medium Severity Findings

#### FINDING-006: Timestamp Certificate Not Validated
- **Severity:** MEDIUM
- **Location:** `tsa.py:130`
- **Code:**
  ```python
  cert = content["certificates"][0].chosen
  ```
- **Description:** Similar to FINDING-005, the TSA certificate is used without validation.
- **Impact:** Malicious timestamp responses could be accepted.
- **Recommendation:** Validate TSA certificate has timestamping EKU and chains to trusted CA.

#### FINDING-007: No Signature Algorithm Enforcement
- **Severity:** MEDIUM
- **Location:** `signature_verifier.py:49-50`
- **Code:**
  ```python
  if hash_algo not in ("SHA256", "SHA384", "SHA512"):
      raise InvalidSignatureAlgorithm(hash_algo)
  ```
- **Description:** While weak hash algorithms (SHA1, MD5) are rejected for direct use, the library doesn't prevent loading signatures that use these algorithms.
- **Impact:** Signatures using deprecated algorithms may be accepted during verification of existing containers.
- **Recommendation:** Add configuration option to reject weak algorithms during verification.

#### FINDING-008: HTTP Used for OCSP/TSA Services
- **Severity:** MEDIUM
- **Location:** `ocsp.py:76-84`, `tsa.py:43-55`
- **Description:** The library accepts any URL for OCSP and TSA services, including plain HTTP.
- **Impact:** Man-in-the-middle attacks could intercept or modify OCSP/TSA responses.
- **Recommendation:** Warn or reject non-HTTPS URLs, or enforce response signature verification.

#### FINDING-009: No Request Timeout Configuration
- **Severity:** MEDIUM
- **Location:** `ocsp.py:84`, `tsa.py:54`
- **Code:**
  ```python
  response = self.session.send(req.prepare())
  ```
- **Description:** HTTP requests to OCSP/TSA services have no explicit timeout.
- **Impact:** Denial of service through slow responses.
- **Recommendation:** Add configurable timeout with sensible defaults (e.g., 30 seconds).

#### FINDING-010: Datetime.utcnow() Deprecation
- **Severity:** LOW
- **Location:** `xmlsig.py:25`
- **Code:**
  ```python
  return datetime.utcnow()
  ```
- **Description:** `datetime.utcnow()` is deprecated in Python 3.12+.
- **Impact:** Future compatibility issues.
- **Recommendation:** Use `datetime.now(timezone.utc)` instead.

### 3.4 Low Severity Findings

#### FINDING-011: Bare Exception Handler
- **Severity:** LOW
- **Location:** `xmlsig.py:517`
- **Code:**
  ```python
  except:  # noqa: E722
      c14n_algo = None
  ```
- **Description:** Bare except clause may mask unexpected errors.
- **Recommendation:** Catch specific exceptions.

#### FINDING-012: Assert Used for Validation
- **Severity:** LOW
- **Location:** `container.py:228, 368`, `xmlsig.py:480`
- **Description:** `assert` statements are used for input validation, which can be disabled with `-O` flag.
- **Recommendation:** Use explicit validation with exceptions.

#### FINDING-013: Logging of Sensitive Data
- **Severity:** LOW
- **Location:** `xmlsig.py:97`
- **Code:**
  ```python
  logger.exception("Failed to load XML document: %s", xml_or_binary_data)
  ```
- **Description:** XML content (potentially containing signatures) is logged on error.
- **Recommendation:** Sanitize or truncate logged data.

#### FINDING-014: No Nonce Verification in OCSP Response
- **Severity:** LOW
- **Location:** `ocsp.py`
- **Description:** The nonce sent in OCSP request is not verified in the response.
- **Impact:** Replay attacks with cached OCSP responses.
- **RFC Reference:** RFC 6960 Section 4.4.1
- **Recommendation:** Verify nonce in response matches request.

---

## 4. Cryptographic Analysis

### 4.1 Supported Algorithms

| Algorithm | Type | Status | Notes |
|-----------|------|--------|-------|
| RSA-SHA256 | Signature | RECOMMENDED | Default algorithm |
| RSA-SHA384 | Signature | ACCEPTABLE | |
| RSA-SHA512 | Signature | ACCEPTABLE | |
| ECDSA-SHA256 | Signature | RECOMMENDED | |
| ECDSA-SHA384 | Signature | ACCEPTABLE | |
| ECDSA-SHA512 | Signature | ACCEPTABLE | |
| SHA-256 | Hash | RECOMMENDED | Primary hash algorithm |
| SHA-384 | Hash | ACCEPTABLE | |
| SHA-512 | Hash | ACCEPTABLE | |
| SHA-1 | Hash | DEPRECATED | Used only in OCSP issuer key hash |

### 4.2 Key Size Requirements

The library does not enforce minimum key sizes. Per NIST SP 800-131A Rev 2:

| Algorithm | Minimum Key Size | Current Enforcement |
|-----------|------------------|---------------------|
| RSA | 2048 bits | NOT ENFORCED |
| ECDSA P-256 | 256 bits | NOT ENFORCED |
| ECDSA P-384 | 384 bits | NOT ENFORCED |
| ECDSA P-521 | 521 bits | NOT ENFORCED |

**Recommendation:** Add key size validation during certificate processing.

### 4.3 Cryptographic Library Analysis

| Library | Version | CVE Status | Notes |
|---------|---------|------------|-------|
| cryptography | >=5 | CURRENT | Well-maintained, regular security updates |
| oscrypto | * | CURRENT | Wrapper around system crypto |
| asn1crypto | * | CURRENT | Pure Python ASN.1 parsing |
| lxml | >=4,<5 | CHECK REQUIRED | XML parsing, check for CVEs |

### 4.4 ECDSA Signature Format Handling

**Location:** `signature_verifier.py:23-32, 60-72`

The library handles both DER and X.962 (raw) ECDSA signature formats:

```python
try:
    ECDSASignature.load(signature)  # Try DER first
except ValueError:
    signature = x962_to_der(signature)  # Convert X.962 to DER
```

**Analysis:** This approach is sound but could be vulnerable to format confusion if the signature happens to be valid in both formats. The library correctly prioritizes DER format.

---

## 5. XML Security Analysis

### 5.1 Canonicalization Methods

| Method | URI | Exclusive | Used For |
|--------|-----|-----------|----------|
| C14N 1.0 | `http://www.w3.org/TR/2001/REC-xml-c14n-20010315` | No | Required default |
| Exclusive C14N | `http://www.w3.org/2001/10/xml-exc-c14n#` | Yes | SignedInfo, SignedProperties |
| C14N 1.1 | `http://www.w3.org/2006/12/xml-c14n11` | No | Alternative |

**Location:** `xmlsig.py:60-64`

**Analysis:** The supported canonicalization methods are appropriate. The template uses Exclusive C14N, which is the recommended method for interoperability.

### 5.2 XML Signature Wrapping (XSW) Attack Surface

The library is potentially vulnerable to several classes of XSW attacks:

1. **Id Duplication:** No check for duplicate Id attributes
2. **Reference Manipulation:** References are resolved by XPath without strict validation
3. **Ancestor Injection:** No validation of signature placement in document

**Mitigation Required:**
- Validate exactly one element matches each Reference URI
- Ensure SignedProperties is a descendant of the Signature element
- Check for duplicate Id attributes

### 5.3 XML Parser Configuration

**Current Configuration (`xmlsig.py:93`):**
```python
parser = etree.XMLParser(remove_blank_text=False, remove_comments=True)
```

**Recommended Configuration:**
```python
parser = etree.XMLParser(
    remove_blank_text=False,
    remove_comments=True,
    resolve_entities=False,      # Prevent XXE
    no_network=True,             # Prevent SSRF via DTD
    dtd_validation=False,        # Don't process DTD
    load_dtd=False,              # Don't load external DTD
    huge_tree=False              # Limit tree size (DoS protection)
)
```

---

## 6. Protocol Implementation Review

### 6.1 OCSP Implementation

#### 6.1.1 Request Building (`ocsp.py:157-189`)

| Field | Implementation | Compliance |
|-------|----------------|------------|
| Version | Not explicitly set (defaults to v1) | COMPLIANT |
| requestList | Single certificate | COMPLIANT |
| requestExtensions | Nonce (SHA-256 of signature) | COMPLIANT |

#### 6.1.2 Response Validation (`ocsp.py:112-149`)

| Check | Implemented | Notes |
|-------|-------------|-------|
| Response status | YES | `ocsp.py:124-126` |
| Signature verification | YES | `ocsp.py:149` |
| Responder cert validation | NO | See FINDING-005 |
| Nonce verification | NO | See FINDING-014 |
| thisUpdate/nextUpdate check | NO | Time validity not checked |
| Certificate status | PARTIAL | Status checked but not individual cert |

#### 6.1.3 SK.ee Compatibility Workaround

**Location:** `ocsp.py:17-29`

```python
class SKHackedTBSRequestExtension(TBSRequestExtension):
    """A workaround class for compatibility with old java libraries used in SK.ee"""
```

**Analysis:** This workaround modifies the ASN.1 structure to use plain `OctetString` instead of `ParsableOctetString` for compatibility with SK.ee's Java implementation. This is documented and acceptable.

### 6.2 TSA Implementation

#### 6.2.1 Request Building (`tsa.py:157-164`)

| Field | Implementation | Compliance |
|-------|----------------|------------|
| version | v1 | COMPLIANT |
| messageImprint | SHA-256 hash | COMPLIANT |
| certReq | TRUE | COMPLIANT |
| nonce | Not implemented | ACCEPTABLE (optional) |
| reqPolicy | Not implemented | ACCEPTABLE (optional) |

#### 6.2.2 Response Validation (`tsa.py:75-142`)

| Check | Implemented | Notes |
|-------|-------------|-------|
| Content type validation | YES | `tsa.py:87-88` |
| Message imprint verification | YES | `tsa.py:97-103` |
| Digest matching | YES | `tsa.py:106-117` |
| Signature verification | YES | `tsa.py:138` |
| TSA cert validation | NO | See FINDING-006 |

---

## 7. Container Security

### 7.1 ZIP Security

| Risk | Mitigation | Status |
|------|------------|--------|
| Zip bomb | None | NOT MITIGATED |
| Path traversal | None explicit | PARTIALLY MITIGATED by ZipFile |
| Symlink attacks | None | NOT APPLICABLE (no extraction) |

**Recommendation:** Add file size and count limits for container operations.

### 7.2 Manifest Validation

**Location:** `container.py:258-296`

| Check | Implemented |
|-------|-------------|
| Mimetype is first entry | YES |
| Mimetype value correct | YES |
| Manifest exists | YES |
| Manifest matches TOC | YES |

### 7.3 Signature File Naming

**Location:** `container.py:57`

```python
SIGNATURE_FILES_REGEX = r"^%s/signatures[^\d]*(\d*)\.xml$" % META_DIR
```

**Analysis:** The regex is appropriate but could be stricter. Per BDOC spec, signature files should be named `signatures*.xml` where `*` is a positive integer.

---

## 8. Test Coverage Analysis

### 8.1 Coverage Summary

| Module | Test File | Coverage |
|--------|-----------|----------|
| `container.py` | `test_container.py` | GOOD |
| `xmlsig.py` | `test_xml_signature.py` | GOOD |
| `ocsp.py` | `test_ocsp.py` | MODERATE |
| `tsa.py` | `test_tsa.py` | MODERATE |
| `signature_verifier.py` | `test_signature_verifier.py` | GOOD |

### 8.2 Missing Test Scenarios

| Scenario | Risk |
|----------|------|
| Malformed XML signatures | XXE, XSW attacks |
| Invalid certificate chains | Trust anchor bypass |
| Expired/revoked certificates | Signature acceptance |
| Weak algorithms | Algorithm downgrade |
| Large files | DoS |
| Unicode edge cases in filenames | Encoding issues |
| Concurrent container access | Race conditions |

---

## 9. Recommendations

### 9.1 Critical (Must Fix for Qualified Signatures)

1. **Implement Certificate Chain Validation**
   - Build and validate certificate path to trusted root
   - Check certificate validity periods
   - Verify key usage extensions
   - Check basic constraints

2. **Validate OCSP Responder Authorization**
   - Verify responder certificate has OCSPSigning EKU
   - Ensure responder is authorized by certificate's issuer

3. **Implement Signature Verification Security**
   - Check embedded OCSP response during verification
   - Validate timestamps during verification
   - Reject weak algorithms

### 9.2 High Priority

4. **Harden XML Parser**
   ```python
   parser = etree.XMLParser(
       resolve_entities=False,
       no_network=True,
       dtd_validation=False,
       load_dtd=False
   )
   ```

5. **Add XSW Attack Mitigations**
   - Validate Reference URI uniqueness
   - Check SignedProperties placement
   - Verify no duplicate Id attributes

6. **Validate TSA Certificate**
   - Check timestamping EKU
   - Validate certificate chain

### 9.3 Medium Priority

7. **Add Network Security**
   - Warn on non-HTTPS URLs
   - Add configurable timeouts
   - Implement retry logic with backoff

8. **Verify OCSP Nonce**
   - Match nonce in response to request

9. **Add Key Size Validation**
   - Minimum 2048-bit RSA
   - Minimum P-256 for ECDSA

### 9.4 Low Priority

10. **Code Quality**
    - Replace `assert` with explicit validation
    - Use specific exception handlers
    - Update deprecated datetime usage

11. **Documentation**
    - Document security considerations
    - Provide secure configuration guidance
    - Add threat model documentation

---

## 10. Compliance Checklist

### 10.1 eIDAS Regulation Requirements

| Requirement | Article | Status | Notes |
|-------------|---------|--------|-------|
| Advanced electronic signature | Art. 26 | PARTIAL | Missing uniqueness linking |
| Qualified electronic signature | Art. 28 | NOT MET | Requires external QES device |
| Signature creation data | Art. 26(a) | EXTERNAL | Depends on signing service |
| Identification of signatory | Art. 26(b) | YES | Via certificate |
| Link to signed data | Art. 26(d) | YES | Via hash references |
| Detect modification | Art. 26(d) | YES | Via signature verification |

### 10.2 XAdES Baseline Profile (ETSI TS 103 171)

| Level | Status | Missing Elements |
|-------|--------|------------------|
| B-B (Basic) | COMPLIANT | None |
| B-T (Timestamp) | COMPLIANT | None |
| B-LT (Long-Term) | PARTIAL | Certificate chain validation |
| B-LTA (Long-Term Archival) | NOT COMPLIANT | Archive timestamps |

### 10.3 BDOC 2.1.2 Specification

| Requirement | Section | Status |
|-------------|---------|--------|
| ASiC-E container format | 6 | COMPLIANT |
| XAdES signature format | 7 | COMPLIANT |
| OCSP confirmation | 8.1 | COMPLIANT |
| Time-stamping | 8.2 | COMPLIANT |
| Signature policy | 7.2.4 | COMPLIANT (Estonian policy) |

---

## Appendix A: Threat Model

### A.1 Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                     TRUSTED ZONE                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Signing   │  │   Trusted   │  │    Time     │         │
│  │   Device    │  │     CAs     │  │   Source    │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
                           │
                    ┌──────┴──────┐
                    │   pyasice   │
                    │   Library   │
                    └──────┬──────┘
                           │
┌─────────────────────────────────────────────────────────────┐
│                    UNTRUSTED ZONE                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  OCSP/TSA   │  │   Network   │  │   Input     │         │
│  │  Services   │  │   Traffic   │  │   Files     │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
```

### A.2 Attack Vectors

| Vector | Risk | Current Mitigation |
|--------|------|-------------------|
| Malformed XML | HIGH | Partial (lxml defaults) |
| XXE | MEDIUM | Partial (lxml defaults) |
| XSW | HIGH | None |
| OCSP spoofing | MEDIUM | Signature verification |
| TSA spoofing | MEDIUM | Signature verification |
| Certificate forgery | HIGH | None (no chain validation) |
| Weak crypto | LOW | Algorithm whitelist |

---

## Appendix B: Code Locations Reference

### B.1 Security-Critical Functions

| Function | File | Line | Purpose |
|----------|------|------|---------|
| `verify()` | `signature_verifier.py` | 35 | Signature verification |
| `XmlSignature.verify()` | `xmlsig.py` | 265 | XML signature verification |
| `OCSP.verify_response()` | `ocsp.py` | 113 | OCSP response verification |
| `TSA.verify()` | `tsa.py` | 75 | TSA response verification |
| `Container.verify_signatures()` | `container.py` | 249 | Container verification |

### B.2 Input Processing Functions

| Function | File | Line | Input Type |
|----------|------|------|------------|
| `XmlSignature.__init__()` | `xmlsig.py` | 89 | XML data |
| `Container.__init__()` | `container.py` | 75 | ZIP stream |
| `OCSP.load()` | `ocsp.py` | 152 | Binary OCSP |
| `TSA.load()` | `tsa.py` | 170 | Binary TSA |

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | January 2026 | Security Audit | Initial comprehensive audit |

---

**Disclaimer:** This audit provides a point-in-time assessment based on the code reviewed. New vulnerabilities may be discovered after this audit. Regular security reviews and dependency updates are recommended.
