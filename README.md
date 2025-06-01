# ElasticDetections

**Elastic Stack home-lab detections** written in Elastic-recommended **TOML** format and mapped to MITRE ATT&CK.  
Rules are stress-tested with Atomic Red Team and validated on every push via GitHub Actions.

---

## Lab Architecture
![architecture](docs/architecture.png)

1. **Elastic Stack 8.x** on Ubuntu │ 2. **Windows 10 VM** (Sysmon)  
3. **Security Onion 2** sensor (Zeek) │ 4. **Atomic Red Team** for attack simulation  

---

## Repository Layout

| Path | Purpose |
|------|---------|
| `rules/` | Detection rules (`<tactic>_<technique>_<desc>.toml`) |
| `tests/` | One Markdown file per rule with ART command + expected alert screenshot |
| `docs/`  | Diagrams and screenshots embedded in this README |
| `.github/workflows/rule-ci.yml` | CI that lints and validates every rule |
| `LICENSE` | MIT—simple, permissive |

---

## Quick Start

```bash
# import dashboards and rules
./scripts/load_rules.sh
# simulate an attack to test alerting
Invoke-AtomicTest T1059.001
