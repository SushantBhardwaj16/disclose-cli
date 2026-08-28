# disclose-cli

**Responsible disclosure report factory** — turn a YAML finding into polished **Markdown + PDF** suitable for HackerOne, VDP, or CERT-In style submissions.

Includes:

- Severity helper (qualitative impact flags)
- PII / secret redaction
- Templates for IDOR, misconfig, info disclosure

## Install

```bash
cd disclose-cli
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Usage

```bash
# starter YAML
disclose-cli init -o my-finding.yaml --type idor

# edit my-finding.yaml, then:
disclose-cli build my-finding.yaml --style hackerone -o out
disclose-cli build my-finding.yaml --style certin --pdf --md

# severity helper
disclose-cli severity --exposes-pii --privilege-escalation --widespread

# redact a raw notes file before pasting into a report
disclose-cli redact notes.txt -o notes.redacted.txt
```

## Finding YAML fields

| Field | Purpose |
|-------|---------|
| `title`, `summary`, `impact`, `remediation` | Core narrative |
| `steps` | List of reproduction steps |
| `request` / `response` | Sanitized PoC |
| `asset`, `endpoint`, `cwe`, `vuln_type` | Metadata |
| `unauthenticated`, `exposes_pii`, … | Auto-severity flags |

## Example

```bash
disclose-cli build examples/idor-example.yaml --style certin -o out
```

## License

MIT — for authorized, ethical disclosure workflows only.
