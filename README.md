# Auto_Recon

A Python-based security analysis tool by Haim_Barby, performing comprehensive reconnaissance on target URLs. Auto_Recon provides insights into DNS records, WHOIS data, security headers, SSL certificates, subdomains, and more.

## Features

- **DNS Records Analysis**: Retrieves `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, and `SOA` records.
- **WHOIS Lookup**: Gathers registration details for domain names.
- **Security Headers**: Checks for essential security headers to evaluate the website's security configuration.
- **SSL Certificate Analysis**: Inspects SSL certificates, including validity, issuer, and expiration status.
- **Subdomain Discovery**: Attempts to discover subdomains associated with the target domain.
- **Breach History**: Checks if the domain has been involved in data breaches (requires a HaveIBeenPwned API key).

## Installation

Before running, make sure you have Python 3 and required packages installed. Clone the repository and set up the environment as follows:

\```bash
# Clone the repository
git clone https://github.com/Haim_Barby/Auto_Recon.git
cd Auto_Recon

# Set up a virtual environment (optional but recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
\```

## Usage

Run the tool by executing the following command:

\```bash
./Auto_Recon.py
\```

You will be prompted to enter a target URL and optionally a HaveIBeenPwned API key for additional breach information. For example:

\```plaintext
   █▄▄ ▄▀█ █▀█     █▀█     █▀▀ █ █▄░█
   █▄█ █▀█ █▀▄ █▄▄     █▄▀     █ █░▀█
Enter target URL: example.com
Enter HaveIBeenPwned API key (optional): YOUR_API_KEY
\```

### Example Output

\```plaintext
════════════════════ DNS Records Analysis ════════════════════
[+] A Records: 192.168.1.1
[+] MX Records: Priority: 10, Server: mail.example.com

════════════════════ WHOIS Information ════════════════════════
[+] Domain Name: example.com
[+] Registrar: Example Registrar Inc.
...
\```

## Notes

- **Auto_Recon** is designed for ethical security testing and educational purposes only.
- Ensure you have proper authorization before scanning any target domains.

---
