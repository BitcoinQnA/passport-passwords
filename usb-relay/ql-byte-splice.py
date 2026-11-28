#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
# SPDX-License-Identifier: GPL-3.0-or-later
"""Join two outbound TCP clients so a USB relay and a QL session can meet.

Holds no keys; bytes are copied unchanged. Bind to a specific address (a Tailscale
IP) so this is not exposed on other interfaces. The machine that runs this only
forwards opaque records.
"""

from __future__ import annotations

import socket
import sys
import threading


def die(message: str) -> None:
    print(f"ql-byte-splice: {message}", file=sys.stderr)
    raise SystemExit(1)


def copy_bytes(source: socket.socket, dest: socket.socket) -> None:
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            dest.sendall(data)
    except OSError:
        pass
    try:
        dest.shutdown(socket.SHUT_WR)
    except OSError:
        pass


def splice(left: socket.socket, right: socket.socket) -> None:
    threads = [
        threading.Thread(target=copy_bytes, args=(left, right), daemon=True),
        threading.Thread(target=copy_bytes, args=(right, left), daemon=True),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


def main() -> None:
    if len(sys.argv) != 3:
        die("usage: ql-byte-splice.py <bind-address> <port>")
    host, port_text = sys.argv[1], sys.argv[2]
    if host in {"0.0.0.0", "::", "*"}:
        die("refusing to bind every interface; pass a Tailscale address")
    try:
        port = int(port_text)
    except ValueError:
        die(f"bad port: {port_text}")

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(2)
    print(f"ql-byte-splice: listening on {host}:{port}", flush=True)
    while True:
        first, first_from = listener.accept()
        print(f"ql-byte-splice: first connection from {first_from[0]}:{first_from[1]}", flush=True)
        second, second_from = listener.accept()
        print(f"ql-byte-splice: second connection from {second_from[0]}:{second_from[1]}; splicing", flush=True)
        first.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        second.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        splice(first, second)
        first.close()
        second.close()
        print("ql-byte-splice: pair closed; waiting for the next two connections", flush=True)


if __name__ == "__main__":
    main()
