import os
import argparse
from twisted.python import log
from twisted.protocols import basic
from twisted.internet import reactor, protocol, endpoints

script_dir = os.path.dirname(os.path.abspath(__file__))

IAC = 255
DONT = 254
DO = 253
WONT = 252
WILL = 251
SB = 250
SE = 240

ECHO = 1
SGA = 3
BINARY = 0
TTYPE = 24
NAWS = 31
NEW_ENVIRON = 39
LINEMODE = 34


class SimpleTelnetProtocol(basic.LineReceiver):
    delimiter = b"\n"
    maxAttempts = 3
    RAW_LOG_MAX = 2048

    def __init__(self):
        self.attempts = 0
        self.expectingPassword = False
        self._telnet_leftover = b""
        self.term_type = None
        self.naws_cols = None
        self.naws_rows = None

    def connectionMade(self):
        client_ip = self.transport.getPeer().host
        client_port = self.transport.getPeer().port
        log.msg(f"TELNET NEW Connection - Client IP: {client_ip}, Port: {client_port}")

        self._send_telnet_negotiation()

        banner = getattr(getattr(self, "factory", None), "banner", None)
        if isinstance(banner, (bytes, bytearray)) and banner:
            self.transport.write(bytes(banner))
        else:
            self.transport.write(b"Welcome to the Telnet Honeypot!\r\n")

        self.promptForUsername()

    def _send_telnet_negotiation(self):
        self.transport.write(
            b"\xff\xfb\x03"
            b"\xff\xfb\x00"
            b"\xff\xfd\x00"
            b"\xff\xfd\x1f"
            b"\xff\xfd\x18"
            b"\xff\xfd\x27"
            b"\xff\xfd\x22"
            b"\r\n"
        )
        reactor.callLater(0.15, self._request_ttype)

    def _request_ttype(self):
        if self.transport is None or getattr(self.transport, "disconnecting", False):
            return
        self.transport.write(bytes([IAC, SB, TTYPE, 1, IAC, SE]))

    def _log_raw(self, direction: str, data: bytes):
        if not data:
            return
        cut = data[: self.RAW_LOG_MAX]
        hx = cut.hex()
        suffix = "" if len(data) <= self.RAW_LOG_MAX else f" ... (truncated, total={len(data)} bytes)"
        log.msg(f"TELNET RAW {direction} {len(data)} bytes: {hx}{suffix}")

    def dataReceived(self, data):
        self._log_raw("RECV", data)
        buf = self._telnet_leftover + (data or b"")
        app, leftover = self._consume_telnet(buf)
        self._telnet_leftover = leftover
        if app:
            return basic.LineReceiver.dataReceived(self, app)
        return None

    def _consume_telnet(self, data: bytes):
        out = bytearray()
        i = 0
        n = len(data)

        while i < n:
            b = data[i]
            if b != IAC:
                out.append(b)
                i += 1
                continue

            if i + 1 >= n:
                break

            cmd = data[i + 1]

            if cmd == IAC:
                out.append(IAC)
                i += 2
                continue

            if cmd in (DO, DONT, WILL, WONT):
                if i + 2 >= n:
                    break
                opt = data[i + 2]
                self._handle_iac_cmd(cmd, opt)
                i += 3
                continue

            if cmd == SB:
                if i + 2 >= n:
                    break
                opt = data[i + 2]
                j = i + 3
                found = False
                while j + 1 < n:
                    if data[j] == IAC and data[j + 1] == SE:
                        found = True
                        break
                    j += 1
                if not found:
                    break
                sb_data = data[i + 3 : j]
                self._handle_subnegotiation(opt, sb_data)
                i = j + 2
                continue

            i += 2

        return bytes(out), data[i:]

    def _iac_reply(self, cmd: int, opt: int):
        self.transport.write(bytes([IAC, cmd, opt]))

    def _handle_iac_cmd(self, cmd: int, opt: int):
        if cmd == DO:
            if opt in (BINARY, SGA, ECHO):
                self._iac_reply(WILL, opt)
            else:
                self._iac_reply(WONT, opt)
            return

        if cmd == DONT:
            self._iac_reply(WONT, opt)
            return

        if cmd == WILL:
            if opt in (NAWS, TTYPE, NEW_ENVIRON, LINEMODE, BINARY, SGA):
                self._iac_reply(DO, opt)
                if opt == TTYPE:
                    reactor.callLater(0.05, self._request_ttype)
            else:
                self._iac_reply(DONT, opt)
            return

        if cmd == WONT:
            self._iac_reply(DONT, opt)
            return

    def _handle_subnegotiation(self, opt: int, sb_data: bytes):
        if opt == NAWS:
            if len(sb_data) >= 4:
                cols = (sb_data[0] << 8) | sb_data[1]
                rows = (sb_data[2] << 8) | sb_data[3]
                if cols > 0:
                    self.naws_cols = int(cols)
                if rows > 0:
                    self.naws_rows = int(rows)
                log.msg(f"TELNET NAWS cols={self.naws_cols} rows={self.naws_rows}")
            return

        if opt == TTYPE:
            if len(sb_data) >= 2 and sb_data[0] == 0:
                term = sb_data[1:].decode("utf-8", errors="replace").strip()
                if term:
                    self.term_type = term
                    log.msg(f"TELNET TERM_TYPE {self.term_type}")
            return

        if opt == NEW_ENVIRON:
            return

        if opt == LINEMODE:
            return

    def _set_server_echo(self, enabled: bool):
        self.transport.write(bytes([IAC, WILL if enabled else WONT, ECHO]))

    def promptForUsername(self):
        self.expectingPassword = False
        self._set_server_echo(False)
        self.transport.write(b"Username: ")

    def promptForPassword(self):
        self.expectingPassword = True
        self._set_server_echo(True)
        self.transport.write(b"Password: ")

    def lineReceived(self, line):
        if line is None:
            return
        line = line.rstrip(b"\r")

        if self.expectingPassword:
            log.msg(f"Received password attempt: {line}")
            self.attempts += 1
            self._set_server_echo(False)

            if self.attempts < self.maxAttempts:
                self.transport.write(b"Wrong password.\r\n")
                self.promptForUsername()
            else:
                log.msg("Maximum attempts reached. Disconnecting client.")
                self.transport.write(b"Too many wrong attempts. Disconnecting.\r\n")
                self.transport.loseConnection()
        else:
            log.msg(f"Received username attempt: {line}")
            self.promptForPassword()

    def connectionLost(self, reason):
        log.msg("Connection lost")


class SimpleTelnetFactory(protocol.ServerFactory):
    protocol = SimpleTelnetProtocol

    def __init__(self, banner: bytes):
        self.banner = banner


def main():
    parser = argparse.ArgumentParser(description="Run a simple Telnet honeypot server.")
    parser.add_argument(
        "--host", type=str, default="0.0.0.0", help="Host to bind the Telnet server to."
    )
    parser.add_argument(
        "--port", type=int, default=2323, help="Port to bind the Telnet server to."
    )
    parser.add_argument(
        "--banner",
        type=str,
        default="Welcome to the Telnet Honeypot!",
        help="Banner text shown on connect.",
    )
    args = parser.parse_args()

    LOG_FILE_PATH = os.path.join(script_dir, "telnet_honeypot.log")
    print(f"TELNET HONEYPOT ACTIVE ON HOST: {args.host}, PORT: {args.port}")
    print(f"ALL attempts will be logged in: {LOG_FILE_PATH}")

    log_observer = log.FileLogObserver(open(LOG_FILE_PATH, "a"))
    log.startLoggingWithObserver(log_observer.emit, setStdout=False)

    banner = (args.banner or "").encode("utf-8", errors="replace")
    if not banner.endswith(b"\r\n"):
        banner += b"\r\n"

    telnet_factory = SimpleTelnetFactory(banner=banner)

    endpoint = endpoints.TCP4ServerEndpoint(reactor, args.port, interface=args.host)
    endpoint.listen(telnet_factory)
    reactor.run()


if __name__ == "__main__":
    main()
