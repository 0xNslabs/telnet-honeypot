# Simple Telnet Honeypot Server

## Introduction
The Simple Telnet Honeypot Server is a lightweight, low-interaction Telnet service intended for capturing and analyzing unauthorized connection and authentication attempts. Implemented in Python using the Twisted networking framework, it emulates common Telnet behaviors (including basic option negotiation) while logging both credentials and raw network bytes to assist in incident response and threat research.

## Features
- **Low-Interaction Honeypot**: Simulates a Telnet login flow (username/password) without providing a real shell.
- **Telnet Option Negotiation**: Performs common Telnet negotiations (e.g., SGA/BINARY, NAWS, terminal type) to better match real clients.
- **Configurable Settings**: Set bind host/port and connection banner using command-line arguments.
- **Extensive Logging**:
  - Logs connection metadata and authentication attempts.
  - Logs **raw received bytes** (hex-encoded, truncated) to help spot unusual payloads and potential zero-day behavior.
  - Logs Telnet telemetry when available (e.g., terminal type, window size).
- **Educational Resource**: Useful for learning about Telnet behaviors, brute-force patterns, and defensive monitoring.

## Requirements
- Python 3.x
- Twisted Python library

## Installation
Clone the repository and install dependencies:

```bash
git clone https://github.com/0xNslabs/telnet-honeypot.git
cd telnet-honeypot
pip install twisted
```

## Usage
Start the server with the following command. By default, it binds to `0.0.0.0` on port `2323`.

```bash
python3 telnet.py --host 0.0.0.0 --port 2323
```

Customize the banner shown to clients on connect:

```bash
python3 telnet.py --host 0.0.0.0 --port 2323 --banner "User Access Verification"
```

## Logging
All events are written to `telnet_honeypot.log`, including:
- New connections (IP/port)
- Username and password attempts
- Telnet option telemetry (when negotiated)
- Raw received bytes (hex), truncated to a safe maximum size per event

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
- [MongoDB Honeypot](https://github.com/0xNslabs/mongodb-honeypot) - Simulates a MongoDB database server.
- [NTP Honeypot](https://github.com/0xNslabs/ntp-honeypot) - Monitors Network Time Protocol interactions.
- [PostgreSQL Honeypot](https://github.com/0xNslabs/postgresql-honeypot) - Simulates a PostgreSQL database server.
- [SIP Honeypot](https://github.com/0xNslabs/sip-honeypot) - Monitors SIP (Session Initiation Protocol) interactions.
- [SSH Honeypot](https://github.com/0xNslabs/ssh-honeypot) - Emulates an SSH server.
- [TELNET Honeypot](https://github.com/0xNslabs/telnet-honeypot) - Simulates a TELNET server.

## Security and Compliance
- **Caution**: Operate this honeypot within a secure and controlled environment.
- **Compliance**: Deploy this honeypot in accordance with applicable laws and regulations.

## License
This project is made available under the MIT License. For more information, see the `LICENSE` file.
