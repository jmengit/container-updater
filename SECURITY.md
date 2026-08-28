# Security Policy

This is a private internal project. Report vulnerabilities privately to the repository owner; do not open a public disclosure.

## Supported version

Only the latest tagged release is supported.

## Threat boundary

v0.1 is report-only and must not be granted Docker socket access, privileged mode, host PID/network namespaces, or writable host paths except its dedicated appdata. The optional report-state mount is read-only.

Any future host runner or execution functionality requires a separate threat model, independent security review, explicit approval, and a new tagged release. Approval intent stored by v0.1 is not authority for host mutation.
