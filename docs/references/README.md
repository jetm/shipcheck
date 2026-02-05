# References

Local copies of regulatory and standards documents that shipcheck checks are mapped against. Kept in-tree so that (a) the `cra_mapping` entries in each check are traceable to verbatim source text and (b) the repo is self-contained for offline work.

## Documents

| File | Source | Notes |
|------|--------|-------|
| `cra-regulation-2024-2847.pdf` | Regulation (EU) 2024/2847 (Cyber Resilience Act), Official Journal of the European Union, 20 November 2024. ELI http://data.europa.eu/eli/reg/2024/2847/oj | 81 pages, authentic PDF. Do not edit. Replace only when a consolidated version supersedes it. |

## Refresh procedure

```bash
curl -sSL -o docs/references/cra-regulation-2024-2847.pdf \
  "https://eur-lex.europa.eu/legal-content/EN/TXT/PDF/?uri=CELEX:32024R2847"
```

EUR-Lex publishes consolidated versions as amendments pass. Check for a newer consolidated version at https://eur-lex.europa.eu/eli/reg/2024/2847 before refreshing.

## Why local copies

Shipcheck's `cra_mapping` metadata on every finding cites specific Annex items (e.g. `"I.P1.d"` for Annex I Part I §(d)). Those citations are only as good as the source text they reference. Keeping the authoritative PDF in-tree means a reviewer can open the regulation and verify a mapping without chasing external URLs.
