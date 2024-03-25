import os
import argparse
from twisted.python import log
from twisted.protocols import basic
from twisted.internet import reactor, protocol, endpoints

script_dir = os.path.dirname(os.path.abspath(__file__))


class SimpleTelnetProtocol(basic.LineReceiver):
    delimiter = b"\n"
    maxAttempts = 3

    def __init__(self):
        self.attempts = 0
        self.expectingPassword = False

    def connectionMade(self):
        client_ip = self.transport.getPeer().host
        client_port = self.transport.getPeer().port
        log.msg(f"TELNET NEW Connection - Client IP: {client_ip}, Port: {client_port}")
        self.transport.write(b"Welcome to the Telnet Honeypot!\r\n")
        self.promptForUsername()

    def promptForUsername(self):
        self.expectingPassword = False
        self.transport.write(b"Username: ")

    def promptForPassword(self):
        self.expectingPassword = True
        self.transport.write(b"Password: ")

    def lineReceived(self, line):
        if self.expectingPassword:
            log.msg(f"Received password attempt: {line}")
            self.attempts += 1
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


def main():
    parser = argparse.ArgumentParser(description="Run a simple Telnet honeypot server.")
    parser.add_argument(
        "--host", type=str, default="0.0.0.0", help="Host to bind the Telnet server to."
    )
    parser.add_argument(
        "--port", type=int, default=2323, help="Port to bind the Telnet server to."
    )
    args = parser.parse_args()

    LOG_FILE_PATH = os.path.join(script_dir, "telnet_honeypot.log")
    print(f"TELNET HONEYPOT ACTIVE ON HOST: {args.host}, PORT: {args.port}")
    print(f"ALL attempts will be logged in: {LOG_FILE_PATH}")

    log_observer = log.FileLogObserver(open(LOG_FILE_PATH, "a"))
    log.startLoggingWithObserver(log_observer.emit, setStdout=False)

    telnet_factory = SimpleTelnetFactory()

    endpoint = endpoints.TCP4ServerEndpoint(reactor, args.port, interface=args.host)
    endpoint.listen(telnet_factory)
    reactor.run()


if __name__ == "__main__":
    main()
