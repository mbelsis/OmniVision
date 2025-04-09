# OmniVision: Multi-Perspective Network Reconnaissance Tool

## Overview

OmniVision is a comprehensive network reconnaissance and security assessment tool, inspired by the multi-faceted vision of a bee. Designed to provide a holistic view of network vulnerabilities and risks, this tool combines multiple scanning techniques and intelligence sources.

## Key Features

- **Multi-target Analysis**: Scan domains, individual IPs, or entire subnets
- **DNS Security Checks**: Verify SPF, DMARC, and other DNS security configurations
- **SSL/TLS Assessment**: Evaluate certificate validity and cipher strength
- **Port Scanning**: Identify open ports and potentially vulnerable services
- **Cloud Exposure Detection**: Discover exposed cloud assets (S3 buckets, Azure blobs, etc.)
- **Typosquatting Detection**: Find similar domains that could be used for phishing
- **Threat Intelligence Integration**: Check targets against known threat databases
- **Risk Scoring**: Quantify security risks with weighted scoring system
- **Multiple Output Formats**: Generate reports in text, HTML, or CSV formats
- **Progress Tracking**: Visual feedback for long-running operations
- **Parallel Processing**: Configurable concurrent operations for faster scanning



## Support This Project

If you enjoy using this app, why not [![Buy Me a Coffee](https://www.buymeacoffee.com/assets/img/custom_images/yellow_img.png)](https://buymeacoffee.com/mbelsis)




## File Structure and Modules

### Main Script Files

- `external_recon_risk_enhanced.py` - Main script with all features and enhancements

### Module Files

- `dns_checks.py` - DNS security configuration checks (SPF, DMARC, MX records)
- `cert_checks.py` - Certificate transparency log checks
- `cloud_checks.py` - Cloud asset exposure detection
- `cloudflare_checks.py` - Cloudflare-specific security checks
- `typosquatting.py` - Typosquatting domain detection

### Configuration Files

- `config.py` - Original configuration file

### Documentation Files

- `debugging_report.md` - Detailed report of issues found and fixes implemented
- `ssl_compatibility_changes.md` - Documentation of changes made for SSL compatibility
- `ssl_installation_instructions.md` - Instructions for resolving SSL issues

## Requirements and Dependencies

### Core Dependencies

```
aiohttp>=3.8.0
shodan>=1.28.0
requests>=2.28.0
typing-extensions>=4.5.0
python-dateutil>=2.8.2
asyncio>=3.4.3
python-whois>=0.8.0
dnspython>=2.3.0
tld>=0.13
idna>=3.4
chardet>=5.1.0
tqdm>=4.65.0
ipaddress>=1.0.23
argparse>=1.4.0
```

### SSL-Related Dependencies

```
pyOpenSSL>=23.2.0
cryptography>=41.0.5
certifi>=2023.7.22
urllib3>=2.0.0
```

### External Tools

- **Nmap**: Required for port scanning functionality

### API Keys (Optional)

The following API keys enhance functionality but are not strictly required:
- Shodan API key
- AbuseIPDB API key
- AlienVault OTX API key
- Censys API credentials

## Installation

### Standard Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/external-recon-risk.git
   cd external-recon-risk
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Install Nmap (if not already installed):
   - **Linux**: 
     ```bash
     sudo apt-get update
     sudo apt-get install nmap
     ```
   - **macOS**: 
     ```bash
     brew install nmap
     ```
   - **Windows**: 
     1. Download the installer from [nmap.org](https://nmap.org/download.html)
     2. Run the installer and follow the installation wizard
     3. **Important**: Add Nmap to your system PATH during installation
        - During installation, check the option to add Nmap to the PATH
        - Alternatively, manually add `C:\Program Files\Nmap` or `C:\Program Files (x86)\Nmap` to your system PATH
     4. Verify installation by opening Command Prompt and running:
        ```
        nmap -V
        ```

### SSL Installation on Windows/Anaconda

If you encounter SSL-related errors on Windows, especially with Anaconda:

1. Install OpenSSL through conda:
   ```bash
   conda install -c anaconda openssl
   ```

2. If errors persist, set environment variables:
   ```bash
   set SSL_CERT_FILE=%CONDA_PREFIX%\Library\ssl\cert.pem
   set SSL_CERT_DIR=%CONDA_PREFIX%\Library\ssl\certs
   ```

3. Alternatively, use the SSL-compatible version of the script (`external_recon_risk_no_ssl.py`)

For detailed SSL troubleshooting, refer to the `ssl_installation_instructions.md` file.

## Usage

### Basic Usage

```bash
python external_recon_risk_enhanced.py example.com
```

### Scan Options

```bash
# Scan a domain with verbose output
python external_recon_risk_enhanced.py example.com --verbose

# Scan an IP address
python external_recon_risk_enhanced.py 192.168.1.1

# Scan a subnet (limited to 100 hosts)
python external_recon_risk_enhanced.py 192.168.1.0/24 --max-hosts 100

# Look back 60 days for typosquatting domains
python external_recon_risk_enhanced.py example.com --days 60
```

### Output Options

```bash
# Generate HTML report
python external_recon_risk_enhanced.py example.com --output html

# Generate CSV findings
python external_recon_risk_enhanced.py example.com --output csv

# Generate all report formats
python external_recon_risk_enhanced.py example.com --output all
```

### Performance Options

```bash
# Increase parallel processing (1-5)
python external_recon_risk_enhanced.py example.com --parallel 3

# Disable progress bars
python external_recon_risk_enhanced.py example.com --no-progress
```

### API Key Configuration

```bash
# Provide API keys via command line
python external_recon_risk_enhanced.py example.com --shodan-key YOUR_KEY --abuseipdb-key YOUR_KEY

# Or set environment variables
export SHODAN_API_KEY=your_key
export ABUSEIPDB_API_KEY=your_key
export OTX_API_KEY=your_key
export CENSYS_API_ID=your_id
export CENSYS_API_SECRET=your_secret
```

## Output Examples

### Risk Levels

The tool assigns one of the following risk levels based on the calculated risk score:
- **CRITICAL**: Score > 100
- **HIGH**: Score > 70
- **MEDIUM**: Score > 40
- **LOW**: Score > 10
- **INFO**: Score ≤ 10

### Sample Output

```
==================================================
EXTERNAL RECONNAISSANCE REPORT FOR example.com
==================================================
Scan Time: 2025-04-09 08:17:51
Target Type: DOMAIN
Risk Level: MEDIUM
Risk Score: 45

FINDINGS SUMMARY
--------------------------------------------------
HIGH Severity Findings:
  1. [Email Security] No DMARC record found
  2. [Vulnerabilities] Found 2 known vulnerabilities for 192.168.1.1

MEDIUM Severity Findings:
  1. [Email Security] SPF record exists but does not end with a strict or soft fail directive
  2. [Exposed Services] Critical service SSH exposed on port 22

IP DETAILS
--------------------------------------------------
IP: 192.168.1.1
  Organization: Example Organization
  Country: United States
  City: New York
  Open Ports: 22, 80, 443
  Services:
    22/tcp - ssh OpenSSH 8.2p1 (protocol 2.0)
    80/tcp - http nginx 1.18.0
    443/tcp - ssl/http nginx 1.18.0

RECOMMENDATIONS
--------------------------------------------------
1. Implement a DMARC record with at least a quarantine policy
2. Implement a proper SPF record with a strict policy (-all)
3. Patch systems to address known vulnerabilities
4. Restrict access to critical services using firewalls
5. Regularly monitor for new vulnerabilities and security issues
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- This tool utilizes various security APIs and open-source tools
- Special thanks to the security community for their continuous research and tools
