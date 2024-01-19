# Simple Telnet Honeypot Server

## Introduction
The Simple Telnet Honeypot Server offers cybersecurity professionals and enthusiasts a straightforward tool for capturing and analyzing Telnet-based interactions. This Python-scripted server, built upon the Twisted network programming framework, simulates a Telnet server to log unauthorized access attempts and helps in identifying potential security breaches.

## Features
- **Low-Interaction Honeypot**: Simulates a Telnet server to safely log authentication attempts without high risk.
- **Configurable Settings**: The host and port settings can be easily modified using command-line arguments.
- **Extensive Logging**: Every interaction, including login credentials, is recorded for in-depth security auditing.
- **Interactive Response Simulation**: Mimics a live Telnet service, providing automated responses to capture more detailed information.
- **Educational Resource**: Great for learning about Telnet service vulnerabilities and network security monitoring.

## Requirements
- Python 3.x
- Twisted Python library

## Installation
Begin by cloning the repository or downloading the `telnet.py` script. Make sure Python and Twisted are installed on your system.

```bash
git clone https://github.com/0xNslabs/telnet-honeypot.git
cd telnet-honeypot
pip install twisted
```

## Usage
Start the server with the following command, specifying host and port if needed. By default, it binds to all interfaces (0.0.0.0) on port 2323.

```bash
python3 telnet.py --host 0.0.0.0 --port 2323
```

## Logging
Interaction logs are saved in telnet_honeypot.log, which contains detailed records of all Telnet commands and login attempts.

## Simple Telnet Honeypot In Action
![Simple Telnet Honeypot in Action](https://raw.githubusercontent.com/0xNslabs/telnet-honeypot/main/PoC.png)
*The above image showcases the Simple Telnet Honeypot server capturing login attempts.*

## Other Simple Honeypot Services

Check out the other honeypot services for monitoring various network protocols:

- [DNS Honeypot](https://github.com/0xNslabs/dns-honeypot) - Monitors DNS interactions.
- [FTP Honeypot](https://github.com/0xNslabs/ftp-honeypot) - Simulates an FTP server.
- [LDAP Honeypot](https://github.com/0xNslabs/ldap-honeypot) - Mimics an LDAP server.
- [HTTP Honeypot](https://github.com/0xNslabs/http-honeypot) - Monitors HTTP interactions.
- [HTTPS Honeypot](https://github.com/0xNslabs/https-honeypot) - Monitors HTTPS interactions.
- [NTP Honeypot](https://github.com/0xNslabs/ntp-honeypot) - Monitors Network Time Protocol interactions.
- [PostgreSQL Honeypot](https://github.com/0xNslabs/postgresql-honeypot) - Simulates a PostgreSQL database server.
- [SIP Honeypot](https://github.com/0xNslabs/sip-honeypot) - Monitors SIP (Session Initiation Protocol) interactions.
- [SSH Honeypot](https://github.com/0xNslabs/ssh-honeypot) - Emulates an SSH server.
- [TELNET Honeypot](https://github.com/0xNslabs/telnet-honeypot) - Simulates a TELNET server.

## Security and Compliance
- **Caution**:  Operate this honeypot within a secure and controlled environment.
- **Compliance**: Deploy this honeypot in accordance with applicable laws and regulations.

## License
This project is made available under the MIT License. For more information, see the LICENSE file.
