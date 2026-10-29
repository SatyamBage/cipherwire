# Security policy

## Supported versions

Only the current v2 code on the default branch is supported. The v1 code retained in git history is insecure and unsupported; see [SECURITY-NOTICE.md](SECURITY-NOTICE.md).

## Reporting a vulnerability

Please use **GitHub private vulnerability reporting** on the repository's **Security** tab. Do not open a public issue for a suspected vulnerability.

Include:

- affected version or commit;
- a minimal reproduction or proof of concept;
- the security impact and any prerequisites;
- whether the issue affects the relay, CLI, browser client, or protocol;
- any suggested fix or mitigation.

Do not include real private keys, message plaintext, or other people's data. Use generated test identities.

## Scope

In scope:

- protocol confusion, signature or replay bypasses;
- key-substitution or identity-binding failures;
- plaintext or private-key exposure;
- relay memory/CPU/disk denial of service with a realistic attack path;
- browser XSS, CSP bypass, or storage abuse;
- TLS/origin/reverse-proxy misconfiguration in the provided deployment files.

Out of scope or explicitly not guaranteed:

- compromise of an endpoint, browser profile, or unlocked CLI session;
- a malicious contact who is already trusted;
- traffic analysis and metadata hiding;
- forward secrecy or post-compromise security (not implemented in v2);
- availability of a single relay, offline delivery, or message history;
- social engineering and fingerprint comparison mistakes.

## Disclosure

Please allow time for a fix and coordinated disclosure. The project will credit reporters who want credit. This is a small experimental project, so response times are best-effort.
