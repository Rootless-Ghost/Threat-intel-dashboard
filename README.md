# Threat Intel Dashboard

A Python-based threat intelligence tool that aggregates IOCs from multiple sources, performs reputation lookups, and displays actionable intelligence for SOC analysts.

## Demo

![Threat Intel Dashboard Demo](demo.png)

## Features

- **IOC Lookup**: Check IPs, domains, and file hashes against threat intelligence sources
- **Multi-Source Aggregation**: Pulls from VirusTotal, AbuseIPDB, and AlienVault OTX
- **Reputation Scoring**: Calculates risk scores based on multiple data points
- **Web Dashboard**: Clean Flask-based interface for easy interaction
- **CLI Mode**: Command-line interface for quick lookups and scripting
- **Export Results**: Save findings to JSON for reporting

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/threat-intel-dashboard.git
cd threat-intel-dashboard
pip install -r requirements.txt
```

## Configuration

Create a `config.yaml` file with your API keys (free tiers available):

```yaml
api_keys:
  virustotal: "your_api_key_here"
  abuseipdb: "your_api_key_here"
  alienvault: "your_api_key_here"
```

Get free API keys:
- [VirusTotal](https://www.virustotal.com/gui/join-us) - 4 requests/min free
- [AbuseIPDB](https://www.abuseipdb.com/register) - 1000 checks/day free
- [AlienVault OTX](https://otx.alienvault.com/) - Free unlimited

## Usage

### Web Dashboard
```bash
python src/app.py
# Open http://localhost:5000
```

### Command Line
```bash
# Look up an IP address
python src/threat_intel.py --ioc 8.8.8.8 --type ip

# Look up a domain
python src/threat_intel.py --ioc evil-domain.com --type domain

# Look up a file hash
python src/threat_intel.py --ioc 44d88612fea8a8f36de82e1278abb02f --type hash

# Export results to JSON
python src/threat_intel.py --ioc 8.8.8.8 --type ip --output results.json
```

## Project Structure

```
threat-intel-dashboard/
├── src/
│   ├── app.py               # Flask web application
│   ├── threat_intel.py      # Core lookup functionality
│   └── providers/           # API provider modules
├── templates/               # HTML templates
├── static/                  # CSS/JS assets
├── output/                  # Exported reports
├── config.yaml              # API configuration
├── requirements.txt
└── README.md
```

## Supported IOC Types

| Type | Description | Sources Checked |
|------|-------------|-----------------|
| IP Address | IPv4/IPv6 addresses | VirusTotal, AbuseIPDB, AlienVault |
| Domain | Domain names | VirusTotal, AlienVault |
| Hash | MD5, SHA1, SHA256 | VirusTotal, AlienVault |
| URL | Full URLs | VirusTotal |

## Risk Scoring

The dashboard calculates a composite risk score (0-100):

| Score | Risk Level | Description |
|-------|------------|-------------|
| 0-20 | Clean | No malicious indicators |
| 21-40 | Low | Minor flags, likely benign |
| 41-60 | Medium | Some suspicious indicators |
| 61-80 | High | Multiple malicious indicators |
| 81-100 | Critical | Confirmed malicious |

## Roadmap

- [x] Project setup
- [x] CLI IOC lookup
- [x] VirusTotal integration
- [x] AbuseIPDB integration  
- [x] Risk scoring
- [x] Web dashboard
- [ ] AlienVault OTX integration
- [ ] Bulk IOC import (CSV)
- [ ] Historical lookup caching
- [ ] MITRE ATT&CK mapping

## Author

**RootlessGhost**

Junior Penetration Tester | SOC Analyst in Training

## License

MIT License - See [LICENSE](LICENSE) for details
