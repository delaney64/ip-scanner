# ip-scanner

A Python CLI tool for gathering multi-source threat intelligence on IP addresses. Queries VirusTotal, GrayNoise, and Shodan in parallel, maps findings to the MITRE ATT&CK framework, and organizes results using the STRIDE threat model. API keys are stored locally using PBKDF2-derived Fernet encryption.

---

## Features

- **Multi-source enrichment** — VirusTotal, GrayNoise, and Shodan in a single run
- **MITRE ATT&CK mapping** — techniques pulled via TAXII and mapped to STRIDE categories
- **Encrypted key storage** — API keys encrypted at rest with a master password (PBKDF2 + AES-128)
- **Rate limiting** — built-in VirusTotal API throttle (4 req/min free tier)
- **IPv4 + IPv6 support** — input validation via Python's `ipaddress` module

---

## Requirements

- Python 3.9+
- API keys for: [VirusTotal](https://www.virustotal.com), [GrayNoise](https://www.greynoise.io), [Shodan](https://shodan.io)

```bash
pip install requests shodan taxii2-client cryptography
```

---

## Setup

**1. Clone the repo**
```bash
git clone https://github.com/delaney64/ip-scanner.git
cd ip-scanner
```

**2. Store your API keys (one-time)**
```bash
python ip-scanner.py --setup
```

Keys are saved to `~/.ip_scanner/config.enc`. The master password is never stored.

**3. Run a scan**
```bash
python ip-scanner.py 8.8.8.8
```

---

## Project Structure

| Class | Purpose |
|---|---|
| `APIKeyHandler` | Encrypts/decrypts API keys using PBKDF2 + Fernet |
| `APIConfig` | Dataclass holding keys for all three services |
| `IPScanner` | Core scanner — queries APIs, formats output |
| `StrideCategory` | Enum mapping STRIDE threat categories |

---

## Known Limitations

- VirusTotal queries use the v2 API (deprecated — v3 migration planned)
- `query_mitre_attack()` uses a static technique mapping; live TAXII queries not yet implemented

---

## License

MIT