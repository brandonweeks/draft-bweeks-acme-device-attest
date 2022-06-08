---
title: "Automated Certificate Management Environment (ACME) Device Identifier Extension"
abbrev: "ACME-DEVICE"
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

This document specifies identifiers and a challenge required to enable the
Automated Certificate Management Environment (ACME) to issue certificates for the identity of a device.

--- middle

# Introduction

The Automatic Certificate Management Environment (ACME) {{RFC8555}} enables administrative entities to prove control over resources such as domain names, and also provides an automated process for generating and issuing certificates attesting to this control. It only defines challenges for domain names.

In order to allow the identity of a device to be included in X.509 certificates, this document specifies how challenges defined in the ACME specification can be used to validate the identity of the device and if the public key used to represent the device in the certificate has a corresponding private key on the device protected by a secure cryptoprocessor.

Several operating systems and hardware vendors have existing functionality for device attestation, enabling a device to generate a cryptographic attestation of its identity, such as:

- [Android Key Attestation](https://source.android.com/security/keystore/attestation)
- [Chrome OS Verified Access](https://developers.google.com/chrome/verified-access/overview)
- TODO: iOS
- [Trusted Platform Module](https://trustedcomputinggroup.org/resource/trusted-platform-module-tpm-summary/)

This specification defines an extension to ACME to issue certificates including a device attestation, which allows the certificate authority to validate the identity of the device requesting the certificate. This is useful for enterprise public key infrastructure (PKI), where the device attestation can be used as part of a client certificate.

The following components are part of the ACME extension described in this document:

- Addition of `permanent-identifier` and `hardware-module` identifier types.
- Addition of the `device-attest-01` challenge type to prove control of the `permanent-identifier` and `hardware-module` identifier types.
- The challenge response payload contains a serialized WebAuthn (TODO:link) attestation statement format instead of an empty JSON object (`{}`).
- Using accounts and external account binding as a mechanism to pre-authenticate requests to an enterprise CA.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Permanent Identifier

In order to issue certificates for devices with ACME, a new ACME identifier type is required for use in ACME authorization objects. This document defines a new ACME identifier type to represent the identity of a device ("permanent-identifier"). This is typically a serial number for the device assigned by the manufacturer.

In alignment with {{!RFC4043}}, the identifier's name does not prescribe the lifetime of the identifier, which is at the discretion of the Assigner Authority. The identity of a device along with the Assigner Authority can be included in the Subject Alternate Name Extension using the PermanentIdentifier form described in {{!RFC4043}}.

<!-- Section 7.4 of RFC 8555 states "Specifications that define new identifier types must specify where in the certificate signing request these identifiers can appear." -->

Clients MAY include this identifier in the certificate signing request (CSR). Alternatively if the server wishes to only issue privacy-preserving certificates, it MAY reject CSRs containing a PermanentIdentifier in the subjectAltName extension.

TODO: add example like the ACME-IP spec has

# Hardware Module

In order to issue certificates for devices which are bound to a device's secure cryptoprocessor with ACME, a new ACME identifier type is required for use in ACME authorization objects. This document defines another new ACME identifier type to represent the identity of a device's secure cryptoprocessor ("hardware-module"). This is typically hardware on the device specifically meant for secure computation, and which was used to generate the public private keypair used to represent the device in the certificate.

<!-- TODO: describe the certificate representation -->
<!-- TODO: describe how the CA assert the key is hardware backed without an identifier -->

If the server includes HardwareModule in the subjectAltName extension the CA MUST verify that the certificate key was generated on the secure cryptoprocessor with the asserted identity and type. The key MUST NOT be able to be exported from the cryptoprocessor.

If the server wishes to issue privacy-preserving certificates, it MAY omit HardwareModule from the subjectAltName extension.

# Device Attestation Challenge

For a device to have a unique device identity, it must exist, and have its identity bound to a secure cryptoprocessor on the device. For a client to prove control over a device, they can provide an attestation statement containing the PermanentIdentifier of the device.

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

This specification borrows the WebAuthn attestation object (TODO: citation) representation as described in Section 6.5.4 of [WebAuthn] for encapsulating attestation formats with these modification:

- The key authorization is used to form attToBeSigned (TODO: citation). This replaces the concatenation of authenticatorData (TODO: citation) and clientDataHash (TODO: citation). attToBeSigned (TODO: citation) is hashed using an algorithm specified by the attestation format.
- The authData (TODO: citation) field is unused and should be omitted.

A client responds with the response object containing the WebAuthn attestation object in the attObj field (TODO: citation) to acknowledge that the challenge can be validated by the server.

On receiving a response, the server constructs and stores the key authorization from the challenge "token" value and the current client account key.

To validate a device attestation challenge, the server performs the following steps:

1. Perform the verification proceedures described in Section 6 of [WebAuthn].
2. Verify that key authorization conveyed by attToBeSigned (TODO: citation) matches the key authorization stored by the server.

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

ACME was originally envisioned for issuing certificates in web PKI, however this extension will primarily be useful in enterprise PKI. The subsection below covers some operational considerations for an ACME-based enterprise CA.

## External Account Binding

An enterprise CA likely intends to only receive requests from authorized devices, such as devices enrolled in an enterprise's mobile device management solution. It is RECOMMENDED that the server require a value for the "externalAccountBinding" field to be
present in "newAccount" requests.

An enterprise CA could intend to limit the number of certificates that can be requested with a given account for a device, including limiting an account to only one certificate. After the desired number of certificates have been issued to an account, the server MAY revoke the account as described in Section 7.1.2 of {{RFC8555}}.

# Acknowledgments

{:numbered="false"}

TODO acknowledge.
