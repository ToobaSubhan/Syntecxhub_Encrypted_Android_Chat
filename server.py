#!/usr/bin/env python3
"""
Encrypted Chat Server
----------------------
Accepts many clients at once (one thread per client) and relays any
encrypted message it receives from one client to every other connected
client. The server never needs to read the plaintext to do this - it
just passes the encrypted bytes along, which is why clients must all
share the same key: they decrypt each other's messages themselves.

Usage:
    python server.py                  (listens on 0.0.0.0:5000)
    python server.py --port 6000
    python server.py --debug          (also decrypts messages to print
                                        them in the server's own console,
                                        for testing only - see README)
"""

import argparse
import logging
import socket
import threading
from datetime import datetime

from crypto_utils import decrypt, recv_framed, send_framed

# Keeps track of every connected client so we can broadcast to them.
# A lock is used because multiple client threads touch this list at once.
clients_lock = threading.Lock()
clients = {}  # socket -> address string, e.g. "127.0.0.1:54321"


def setup_logging(log_file):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
        handlers=[logging.FileHandler(log_file, encoding="utf-8"), logging.StreamHandler()],
    )


def broadcast(data: bytes, sender_sock) -> None:
    """Send data to every connected client except the one who sent it."""
    with clients_lock:
        dead = []
        for sock in clients:
            if sock is sender_sock:
                continue
            try:
                send_framed(sock, data)
            except OSError:
                dead.append(sock)  # that client disconnected mid-broadcast
        for sock in dead:
            clients.pop(sock, None)


def handle_client(sock, addr, debug):
    addr_str = f"{addr[0]}:{addr[1]}"
    with clients_lock:
        clients[sock] = addr_str
    logging.info("Client connected: %s (total: %d)", addr_str, len(clients))

    try:
        while True:
            data = recv_framed(sock)
            if data is None:
                break  # client disconnected

            # We only log metadata by default (size, time, sender) rather
            # than the plaintext message, so the log doesn't defeat the
            # purpose of encrypting the messages in the first place.
            logging.info("Message from %s: %d encrypted bytes", addr_str, len(data))

            if debug:
                # --debug is for YOUR testing only: it proves the server
                # holds the same key and can read traffic if it wanted to.
                # This is exactly why a pre-shared key that the server also
                # knows is weaker than true end-to-end encryption between
                # clients only - see the README's "Key handling" section.
                try:
                    plaintext = decrypt(data).decode(errors="replace")
                    logging.info("  [debug] decrypted: %s", plaintext)
                except Exception as exc:
                    logging.warning("  [debug] could not decrypt: %s", exc)

            broadcast(data, sock)

    except (ConnectionError, OSError) as exc:
        logging.info("Client %s disconnected (%s)", addr_str, exc)
    finally:
        with clients_lock:
            clients.pop(sock, None)
        sock.close()
        logging.info("Client removed: %s (total: %d)", addr_str, len(clients))


def main():
    parser = argparse.ArgumentParser(description="Encrypted multi-client chat server.")
    parser.add_argument("--host", default="0.0.0.0", help="address to listen on (default: 0.0.0.0, all interfaces)")
    parser.add_argument("--port", type=int, default=5000, help="port to listen on (default: 5000)")
    parser.add_argument("--debug", action="store_true", help="decrypt and print messages for testing")
    parser.add_argument("--log-file", default="server.log", help="file to save logs in")
    args = parser.parse_args()

    setup_logging(args.log_file)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((args.host, args.port))
    server_sock.listen()

    logging.info("Server listening on %s:%d%s", args.host, args.port, " (debug mode)" if args.debug else "")

    try:
        while True:
            client_sock, addr = server_sock.accept()
            # One thread per client so many people can chat at once.
            thread = threading.Thread(target=handle_client, args=(client_sock, addr, args.debug), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        logging.info("Shutting down.")
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()
