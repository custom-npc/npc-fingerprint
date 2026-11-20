# Security policy

## Reporting a vulnerability in npc-fingerprint

Please report privately through GitHub's "Report a vulnerability" (Security tab) instead of a public issue. Include the version (`npc-fingerprint --version`), what you did and what you expected. You will get an acknowledgement and a fix or an explanation.

## Scope notes

- The tool fetches untrusted web content. Findings such as terminal-escape injection, regex denial of service, path traversal while reading archives, or unsafe handling of downloaded data are in scope.
- Everything printed or written to JSON that originates from a target is untrusted text; consumers should escape it.
- Secrets found on targets are redacted by design. A way to make the tool print or store one in full is a vulnerability.

## Responsible use

Use the tool only on systems you own or are authorised to assess.
