#!/usr/bin/env python3
"""No upstream DNS: answer exact loopback fixture names; record every other query."""
import argparse
from pathlib import Path
import socketserver
import struct
import threading

from policy import reserved, denied_read


def response(packet, receipt):
    cursor, labels = 12, []
    while packet[cursor]:
        size = packet[cursor]
        if size > 63:
            raise ValueError('compressed or malformed question')
        labels.append(packet[cursor + 1:cursor + 1 + size].decode('ascii'))
        cursor += size + 1
    name = '.'.join(labels).lower()
    end = cursor + 5
    kind, klass = struct.unpack('!HH', packet[cursor + 1:end])
    allowed = name in ('localhost', '127.0.0.1.nip.io')
    if not allowed:
        report = receipt.with_suffix(receipt.suffix + '.reported') if reserved(name) or denied_read(name, 'GET') else receipt
        with report.open('a') as out:
            out.write(name + '\n')
            out.flush()
    answer = b''
    if allowed and klass == 1 and (kind == 1 or (kind == 28 and name == 'localhost')):
        address = b'\x7f\x00\x00\x01' if kind == 1 else b'\0' * 15 + b'\1'
        answer = b'\xc0\x0c' + struct.pack('!HHIH', kind, 1, 0, len(address)) + address
    header = packet[:2] + struct.pack('!HHHHH', 0x8180 if allowed else 0x8183, 1, bool(answer), 0, 0)
    return header + packet[12:end] + answer


class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        packet, sock = self.request
        sock.sendto(response(packet, self.server.receipt), self.client_address)


class TCP(socketserver.StreamRequestHandler):
    def handle(self):
        length = self.rfile.read(2)
        if len(length) == 2:
            packet = self.rfile.read(struct.unpack('!H', length)[0])
            answer = response(packet, self.server.receipt)
            self.wfile.write(struct.pack('!H', len(answer)) + answer)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--log', type=Path, required=True)
    args = parser.parse_args()
    args.log.open('x').close()
    udp = socketserver.ThreadingUDPServer(('0.0.0.0', 53), UDP)
    tcp = socketserver.ThreadingTCPServer(('0.0.0.0', 53), TCP)
    udp.receipt = tcp.receipt = args.log
    threading.Thread(target=tcp.serve_forever, daemon=True).start()
    udp.serve_forever()


if __name__ == '__main__':
    main()
