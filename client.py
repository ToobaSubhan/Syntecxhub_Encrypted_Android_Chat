#!/usr/bin/env python3
"""
Terminal Chat Client (for testing)
------------------------------------
A simple command-line client that speaks the same protocol the Android
app will use. Run two or more of these against the same server to prove
the server and the encryption work before building the Android side.

Usage:
    python client.py --name Alice
    python client.py --name Bob --host 192.168.1.10 --port 5000
"""

import argparse
import socket
import threading

from crypto_utils import encrypt, decrypt, send_framed, recv_framed


def listen_for_messages(sock):
    """Runs in the background: waits for incoming messages and prints them."""
    while True:
        data = recv_framed(sock)
        if data is None:
            print("\n[Disconnected from server]")
            break
        try:
            text = decrypt(data).decode()
            print(f"\n{text}\n> ", end="", flush=True)
        except Exception:
            print("\n[Received a message that could not be decrypted]\n> ", end="", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Terminal client for the encrypted chat server.")
    parser.add_argument("--name", required=True, help="your display name")
    parser.add_argument("--host", default="127.0.0.1", help="server address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="server port (default: 5000)")
    args = parser.parse_args()

    sock = socket.create_connection((args.host, args.port))
    print(f"Connected to {args.host}:{args.port} as {args.name}. Type a message and press Enter.")

    # Listening happens on its own thread so we can type and receive at the same time.
    threading.Thread(target=listen_for_messages, args=(sock,), daemon=True).start()

    try:
        while True:
            text = input("> ")
            if not text:
                continue
            full_message = f"{args.name}: {text}"
            send_framed(sock, encrypt(full_message.encode()))
    except (KeyboardInterrupt, EOFError):
        print("\nClosing connection.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
