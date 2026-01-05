# IP2INTEL

**IP2INTEL** is a Python-based command-line tool designed to gather comprehensive security and network intelligence about a given IP address from multiple sources. The tool assists security analysts and system administrators in quickly verifying the reputation, geographic location, and technical background of IP addresses.

## Key Features

The software follows a modular architecture and retrieves data from the following sources:

* **Network Information**: Retrieves ASN, network name, owner, CIDR, and country via the RDAP protocol.
* **AbuseIPDB Integration**: Checks the reputation of the IP address, including its abuse confidence score, total reports, ISP, and domain information.
* **DNS Information**: Performs Reverse DNS (PTR) lookups, verifies Forward-Confirmed Reverse DNS (FCrDNS) matches, and queries for A, MX, NS, TXT, and SOA records.
* **VirusTotal Intelligence**: Displays community votes, reputation points, detected threats, and analysis statistics from various engines.
* **Proxy and VPN Detection**: Identifies if the IP is associated with a VPN, proxy, or Tor node, and provides risk scores and anonymity levels.
* **GreyNoise v3**: Identifies mass scanners, business services, threat actors, and trust levels.

## Requirements

* **Python**: Version 3.13 or higher.
* **Required Libraries**: `requests`, `python-dotenv`, `rich`, `ipwhois`, and `dnspython`.

## Installation

1.  Clone the repository or download the source files.
2.  Create a virtual environment (optional but recommended):
    ```bash
    python -m venv .venv
    source .venv/bin/activate  # Linux/macOS
    .venv\Scripts\activate     # Windows
    ```
3.  Install the dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Configuration

The program requires API keys to function, which must be stored in a `.env` file in the project's root directory. 

### Step-by-Step API Setup

1. **Create the file**: In the root directory of the project (where `main.py` is located), create a new file named `.env`.
   - **Windows**: Right-click > New > Text Document, then rename it to `.env` (ensure there is no `.txt` extension).
   - **Linux/macOS**: Run `touch .env` in your terminal.

2. **Obtain API Keys**: Register for a free account at each of the following providers to get your keys:
   - **AbuseIPDB**: [https://www.abuseipdb.com/](https://www.abuseipdb.com/)
   - **VirusTotal**: [https://www.virustotal.com/](https://www.virustotal.com/)
   - **ProxyCheck**: [https://proxycheck.io/](https://proxycheck.io/)
   - **GreyNoise**: [https://www.greynoise.io/](https://www.greynoise.io/)

3. **Fill the file**: Open the `.env` file with a text editor and paste the following template, replacing the placeholders with your actual keys:

```env
ABUSEIPDB_KEY=your_abuseipdb_key_here
VT_API_KEY=your_virustotal_key_here
PROXYCHECK_API_KEY=your_proxycheck_key_here
GREYNOISE_API_KEY=your_greynoise_key_here
