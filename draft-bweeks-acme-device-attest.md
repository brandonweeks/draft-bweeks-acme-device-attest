---
title: "Automated Certificate Management Environment (ACME) Device Attestation Extension"
abbrev: "ACME DA"
category: std
submissiontype: IETF

docname: draft-bweeks-acme-device-attest-latest
v: 3
area: Security
workgroup: ACME Working Group
keyword: Internet-Draft

author:
 -
    fullname: Brandon Weeks
    organization: Google
    email: bweeks@google.com

normative:
  RFC4043:
  RFC8555:
  WebAuthn:
    title: "Web Authentication: An API for accessing Public Key Credentials Level 2"
    author:
      -
        fullname: Jeff Hodges
        organization: Google
        email: jdhodges@google.com
      -
        fullname: J.C. Jones
        organization: Mozilla
        email: jc@mozilla.com
      -
        fullname: Michael B. Jones
        organization: Microsoft
        email: mbj@microsoft.com
      -
        fullname: Akshay Kumar
        organization: Microsoft
        email: akshayku@microsoft.com
      -
        fullname: Emil Lundberg
        organization: Yubico
        email: emil@yubico.com
    date: 2021-04
    target: https://www.w3.org/TR/webauthn-2/
informative:


--- abstract

This document specifies new identifiers and a challenge for the
Automated Certificate Management Environment (ACME) protocol which allows validating the identity of a device using attestation.

--- middle

# Introduction
The Automatic Certificate Management Environment (ACME) {{RFC8555}} standard specifies methods for validating control over identifiers, such as domain names. It is also useful to be able to validate properties of the device requesting the certificate, such as the identity of the device and if the certificate key is protected by a secure cryptoprocessor.

Many operating systems and device vendors offer functionality enabling a device to generate a cryptographic attestation of their identity, such as:

- [Android Key Attestation](https://source.android.com/security/keystore/attestation)
- [Chrome OS Verified Access](https://developers.google.com/chrome/verified-access/overview)
- [Trusted Platform Module](https://trustedcomputinggroup.org/resource/trusted-platform-module-tpm-summary/)

Using ACME and device attestation to issue client certificates for enterprise PKI is anticipated to be the most common use case. The following variances to the ACME specification are described in this document:

- Addition of `permanent-identifier` and `hardware-module` identifier types.
- Addition of the `device-attest-01` challenge type to prove control of the `permanent-identifier` and `hardware-module` identifier types.
- The challenge response payload contains a serialized WebAuthn attestation statement format instead of an empty JSON object (`{}`).
- Accounts and external account binding being used as a mechanism to pre-authenticate requests to an enterprise CA.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Permanent Identifier
A new identifier type, "permanent-identifier" is introduced to represent the identity of a device assigned by the manufacturer, typically a serial number. The name of this identifier type was chosen to align with {{!RFC4043}}, it does not prescribe the lifetime of the identifier, which is at the discretion of the Assigner Authority.

The identity along with the assigning organization can be included in the Subject Alternate Name Extension using the PermanentIdentifier form described in {{!RFC4043}}.

<!-- Section 7.4 of RFC 8555 states "Specifications that define new identifier types must specify where in the certificate signing request these identifiers can appear." -->

The server MAY allow the client to include this identifier in the certificate signing request (CSR). Alternatively if the server wishes to only issue privacy-preserving certificates, it MAY reject CSRs containing a PermanentIdentifier in the subjectAltName extension.

# Hardware Module
A new identifier type, "hardware-module" is introduced to represent the identity of the secure cryptoprocessor, if any, that generated the certificate key.

(TODO describe the certificate representation)

If the server includes HardwareModule in the subjectAltName extension the CA MUST verify that the certificate key was generated on the secure cryptoprocessor with the asserted identity and type. The key MUST NOT be able to be exported from the cryptoprocessor.

If the server wishes to issue privacy-preserving certificates, it MAY omit HardwareModule from the subjectAltName extension.

# Device Attestation Challenge
The client can prove control over a permanent identifier of a device by
providing an attestation statement containing the identifier of the device.

The device-attest-01 ACME challenge object has the following format:

type (required, string):
: The string "device-attest-01".

token (required, string):
: A random value that uniquely identifies the challenge.  This value MUST have
at least 128 bits of entropy. It MUST NOT contain any characters outside the
base64url alphabet, including padding characters ("="). See {{!RFC4086}} for
additional information on randomness requirements.

~~~~~~~~~~
{
  "type": "device-attest-01",
  "url": "https://example.com/acme/chall/Rg5dV14Gh1Q",
  "status": "pending",
  "token": "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA"
}
~~~~~~~~~~

 A client fulfills this challenge by constructing a key authorization ({{!RFC4086}} Section 8.1)
 from the "token" value provided in the challenge and the client's
 account key. The client then generates an WebAuthn attestation object using the key authorization as the challenge.

This specification borrows the WebAuthn _attestation object_ representation as described in Section 6.5.4 of [WebAuthn] for encapsulating attestation formats with these modification:

- The key authorization is used to form _attToBeSigned_. This replaces the concatenation of _authenticatorData_ and _clientDataHash_. _attToBeSigned_ is hashed using an algorithm specified by the attestation format.
- The _authData_ field is unused and should be omitted.

A client responds with the response object containing the WebAuthn attestation object in the "attObj" field to acknowledge that the challenge can be validated by the server.

On receiving a response, the server constructs and stores the key authorization from the challenge "token" value and the current client account key.

To validate a device attestation challenge, the server performs the following steps:

1. Perform the verification proceedures described in Section 6 of [WebAuthn].
2. Verify that key authorization conveyed by _attToBeSigned_ matches the key authorization stored by the server.

<!-- This specification defines a new challenge response field `attObj` to contain WebAuthn attestation objects as described in Section 7.5.1 of {{!RFC8555}}. -->

~~~~~~~~~~
POST /acme/chall/Rg5dV14Gh1Q
Host: example.com
Content-Type: application/jose+json

{
  "protected": base64url({
    "alg": "ES256",
    "kid": "https://example.com/acme/acct/evOfKhNU60wg",
    "nonce": "SS2sSl1PtspvFZ08kNtzKd",
    "url": "https://example.com/acme/chall/Rg5dV14Gh1Q"
  }),
  "payload": base64url({
    "attObj": base64url(/* WebAuthn attestation object */),
  }),
  "signature": "Q1bURgJoEslbD1c5...3pYdSMLio57mQNN4"
}
~~~~~~~~~~

# Security Considerations

TODO Security


# IANA Considerations

## ACME Identifier Types

The "ACME Validation Methods" registry is to be updated to include the following entry:

| Label                | Reference |
| :------------------- | :-------- |
| permanent-identifier | RFC XXXX  |
| hardware-module      | RFC XXXX  |

## ACME Validation Method

The "ACME Validation Methods" registry is to be updated to include the following entry:

| Label            | Identifier Type      | Reference |
| :--------------- | :------------------- | :-------- |
| device-attest-01 | permanent-identifier | RFC XXXX  |


--- back

# Enterprise PKI
ACME was originally envisioned for issuing certificates in the Web PKI, however this extension will primarily be useful in enterprise PKI. The subsection below covers some operational considerations for an ACME-based enterprise CA.

## External Account Binding
An enterprise CA likely only wants to receive requests from authorized devices. It is RECOMMENDED that the server require a value for the "externalAccountBinding" field to be
present in "newAccount" requests.

If an enterprise CA desires to limit the number of certificates that can be requested with a given account, including limiting an account to a single certificate. After the desired number of certificates have been issued to an account, the server MAY revoke the account as described in Section 7.1.2 of {{RFC8555}}.

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
