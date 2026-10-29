# CTAP2 `credProtect`

The credential protection policy is stored per credential in the encrypted
credential record. New credentials default to level 1 and may request levels 1
through 3 with `credProtect`; legacy records migrate as level 1. Policy level 2
requires verified authorization to discover a discoverable credential without
an allow list. Level 3 requires verified authorization for every assertion.

Verified authorization means a ClientPIN token carrying the verified bit and a
matching assertion permission and RP scope. Local user presence alone does not
count as user verification. An unsupported or unsatisfied policy fails closed.

Credential Management enumeration returns the stored `credProtect` value.
GetInfo advertises the extension only when policy persistence, creation,
assertion enforcement, and enumeration are all available. The authenticator
continues to advertise `FIDO_2_0` until the remaining CTAP 2.1 mandatory
requirements are implemented.

Browser interoperability and signed platform distribution remain separate
validation gates.
