# O.43 Native iPhone Role 1 Protocol

Canonical phase: **O.43 Native PhilCore iPhone Companion Foundation and
Secure Enclave Recovery Credential**.

Classification: `LOCAL_ONLY_NATIVE_IOS_COMPANION_IMPLEMENTATION`.

## Decision

Standard recovery now targets:

1. Primary Mac recovery credential.
2. Native PhilCore iPhone companion credential.
3. Offline recovery factor.

Enhanced recovery retains the external-hardware-key Role 1 option. Safari
and ordinary passkeys are not the native iPhone path. Role IDs remain `0`,
`1`, and `2`; valid bitmaps remain `3`, `5`, and `6`; the threshold remains
exact 2-of-3; the execution validator never counts.

## Native descriptor and verifier kind

The native credential uses verifier kind `4`,
`NATIVE_DEVICE_P256`. It does not reinterpret WebAuthn evidence.

```text
PhilCoreV2NativeDeviceP256DescriptorV1(
  uint8 descriptorVersion,
  bytes32 accountVersionId,
  bytes32 securityModelId,
  bytes32 recoveryDomainId,
  uint8 role,
  uint8 verifierKind,
  bytes32 publicVerificationMaterialHash,
  bytes32 credentialIdentifierCommitment,
  bytes32 applicationIdentityHash,
  bytes32 deviceCustodyCommitment,
  bytes32 localApprovalPolicyHash,
  bytes32 appAttestCommitment,
  uint64 credentialGeneration,
  bool secureEnclaveRequired,
  bool simulatorCredential
)
```

The descriptor version is `1`, role is `1`, verifier kind is `4`, and the
recovery domain is
`keccak256("PHILCORE_NATIVE_DEVICE_P256_ROLE1_V1")`.

The application identity is the exact UTF-8 string:

```text
PHILCORE_IOS_NATIVE_ROLE1_V1|B342738S82|com.philcore.ios.companion.localalpha
```

`applicationIdentityHash` is SHA-256 of that string. The verifier pins the
result. The local-approval policy is:

```text
PHILCORE_LOCAL_APPROVAL_V1|DEVICE_OWNER_AUTHENTICATION|FOREGROUND_ONLY|EXACT_DIGEST
```

`localApprovalPolicyHash` is SHA-256 of that exact value and is also pinned.
The P-256 public-material and descriptor commitments use canonical ABI
encoding and Keccak-256.

`appAttestCommitment` is zero in O.43 and means
`DEFERRED_OPTIONAL_ENROLLMENT_ATTESTATION`.

The native evidence contains the descriptor, factor commitment, P-256
coordinates, and an ECDSA signature over the exact existing recovery digest.
The O.37.4 outer recovery envelope remains version `2`. Account version,
recovery configuration version `3`, account storage, account ABI, factory
source, and factory ABI remain unchanged.

The Solidity verifier checks a descriptor claim that Secure Enclave is
required and that the credential is not a simulator credential. A public key
or boolean does not independently prove Apple hardware authenticity.
Enrollment policy and physical testing establish the local custody property;
future App Attest may add optional enrollment evidence.

## Desktop-to-iPhone pairing V1

The desktop binds an HTTP listener to one selected RFC1918 IPv4 address, never
`0.0.0.0`, loopback, or a public address. Direct IP was selected over
Multipeer Connectivity for the first implementation because it is testable
from Electron and native iOS without introducing peer-discovery identity as a
second trust system. Bonjour is not required.

The QR carries only:

- protocol version;
- 256-bit session ID;
- five-minute expiry;
- private-LAN endpoint;
- desktop ephemeral P-256 public key;
- 256-bit challenge;
- PhilCore identity commitment;
- account and security version IDs;
- recovery epoch and requested generation;
- exact application identity.

It contains no recovery secret, private key, reusable authority, production
signature, desktop validator, or long-lived bearer token.

Both sides form this exact UTF-8 transcript:

```text
PHILCORE_NATIVE_PAIRING_V1
<protocolVersion>
<sessionId>
<expiresAt>
<endpoint>
<desktopEphemeralPublicKey>
<challenge>
<philCoreIdentityCommitment>
<accountVersionId>
<securityModelId>
<recoveryEpoch>
<requestedGeneration>
<applicationIdentity>
```

The short comparison value is the first 96 bits of SHA-256 of that transcript,
displayed as six groups of four hexadecimal characters. It is an
anti-substitution comparison value, not an authentication secret.

The iPhone creates an ephemeral P-256 ECDH key. Both sides derive:

```text
HKDF-SHA256(
  ECDH shared secret,
  salt = SHA256(pairing transcript),
  info = "PHILCORE_NATIVE_PAIRING_AES256_GCM_V1",
  length = 32
)
```

The phone response is AES-256-GCM protected with direction-specific AAD
`PHONE_TO_DESKTOP|<sessionId>`. The acknowledgement uses
`DESKTOP_TO_PHONE|<sessionId>`. Nonces are random 96-bit values. The response
binds the public credential, credential identifier commitment, application
identity, custody commitment, approval policy, generation, simulator and
Secure Enclave classifications, and an enrollment signature over the
transcript hash.

The desktop verifies all fields, the ECDSA signature, expiry, single use,
generation, exact application policy, and independence aliases before
retaining encrypted public metadata. A replay returns no success. Unknown
paths, oversized bodies, public interfaces, malformed JSON, altered GCM data,
and wrong identities fail closed.

TLS is not the pairing trust anchor. O.43 uses application encryption and
transcript binding. `NSAllowsLocalNetworking` is declared narrowly for the
private-IP local transport. A later revision may add pinned local TLS without
removing application-level cryptography.

## Recovery signing

The iPhone P-256 credential signs the existing PhilCore EIP-712 recovery
digest directly. It does not sign an opaque arbitrary blob presented by the
renderer. The native UI model requires action classification, account,
network, recovery epoch, expiry, and digest before approval. The Keychain key
is protected by `userPresence | privateKeyUsage`, and the evaluated
`deviceOwnerAuthentication` context is supplied to the key operation.

App backgrounding invalidates the authentication context and cancels the
ephemeral pairing URL session. User cancellation, denial, device-security
failure, key absence, signing failure, transport failure, and desktop
rejection are distinct application errors.

The recovery approval transport after enrollment is foundation-only in O.43.
No production recovery signature was created.

## App Attest

App Attest is deferred and optional. Apple describes it as a server-validated
claim that a key belongs to a legitimate instance of an app on Apple
hardware. Attestation calls an Apple server, requires a registered App ID,
is not supported by every device type, and has separate development and
production environments.

An acceptable future design checks App Attest once during enrollment, verifies
the object in a reviewed local or PhilCore service boundary, and records a
commitment to the result. Recovery-event signature verification remains local
P-256 verification and must not require Apple network availability.

References:

- [Apple: Establishing your app’s integrity](https://developer.apple.com/documentation/DeviceCheck/establishing-your-app-s-integrity)
- [Apple: Preparing to use App Attest](https://developer.apple.com/documentation/DeviceCheck/preparing-to-use-the-app-attest-service)
- [Apple: NSAllowsLocalNetworking](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nsallowslocalnetworking)
