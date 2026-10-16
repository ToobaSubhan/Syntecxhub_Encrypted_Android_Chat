# Encrypted Chat App

A real-time encrypted chat system built for the **Syntecxhub Cybersecurity Virtual Internship** (Week 2). It has two parts that talk to each other over the same network protocol:

- **`server/`** — a multi-client TCP relay server written in Python
- **`android-app/`** — an Android chat client written in Flutter (Dart)

A terminal test client (`server/client.py`) is also included so the system can be tested without a second physical device.

## How It Works

Every message is encrypted with **AES-256-GCM** before it ever touches the network. GCM mode does two things at once: it hides the message content, and it lets the receiving side detect if even one byte was changed in transit - tampered data is rejected outright rather than silently corrupted.

Each message gets its own random 12-byte nonce. Reusing a nonce with the same key is the one mistake that breaks GCM's guarantees, so a fresh one is generated for every message sent, on both the Python and Dart sides.

Because TCP is a stream of bytes with no built-in concept of "one message," every encrypted payload is preceded by a 4-byte big-endian length header stating exactly how many bytes follow. Both sides use this identical framing, which was stress-tested earlier in development with 20 messages sent back-to-back with zero delay - all arrived in order with no merging or splitting.

The server relays encrypted bytes between connected clients without needing to read them - it only decrypts anything when explicitly started with `--debug`, for testing purposes.

Both the Python and Dart implementations were directly cross-tested against each other (Python-encrypted messages decrypted correctly on the Dart/Java side and vice versa) before being wired into the full app, confirming the two languages produce byte-identical ciphertext layouts.

## Folder Structure

```
server/
  server.py          # multi-client relay server
  client.py           # terminal test client
  crypto_utils.py     # shared AES-256-GCM + framing logic (Python side)
android-app/
  lib/
    main.dart          # app entry point, Chats/Status/Calls tabs
    chat_screen.dart    # the real chat UI, wired to ChatClient
    chat_client.dart    # TCP socket handling + framing (Dart side)
    crypto_utils.dart   # AES-256-GCM encryption (Dart side)
```

## Running It

### 1. Start the server
```bash
cd server
pip install cryptography
python server.py --debug
```
`--debug` decrypts messages to the console so you can visually confirm encryption end to end - this is for testing only, see "Key handling" below.

### 2. Run the Android app
Open `android-app/` in Android Studio. In `lib/chat_client.dart` (or `ServerConfig`), set the host to your computer's actual local network IP (from `ipconfig`) - never `127.0.0.1`, which on a phone means "this phone," not your computer. The phone and the computer running the server must be on the same WiFi network, and that WiFi must be set to **Private** in Windows (a Public profile silently blocks the connection).

Run the app, tap a contact, and it connects automatically.

### 3. (Optional) Terminal test client
To test without a second device:
```bash
cd server
python client.py --name Ali
```
Messages sent from the phone appear in this terminal, and vice versa.

## Real Test Output

A full two-way conversation between the Android app and the terminal client, verified against the server's own log at the same timestamps - the decrypted server log, the terminal, and the phone screen all show identical message content, confirming encryption, relay, and decryption all worked correctly in both directions:

```
Server log (--debug):
16:05:47 [INFO] Message from 192.168.1.101:34494: 35 encrypted bytes
16:05:47 [INFO]   [debug] decrypted: Hi 👋
16:06:26 [INFO] Message from 127.0.0.1:56986: 52 encrypted bytes
16:06:26 [INFO]   [debug] decrypted: Ali: Hello! How are you?
...

Phone screen (chat_screen.dart):
  [sent]     Hi 👋
  [received] Ali: Hello! How are you?
  [sent]     I wanted to reach out regarding a small matter, at your convenience.
  [received] Ali: What did you do?
```

A longer follow-up session also confirmed the system recovers correctly from a real disconnect: the Android client's connection was forcibly closed mid-session (`WinError 10054`, which happens when a mobile app is backgrounded or the network briefly drops). The server logged the disconnect cleanly, removed the client without crashing, and the app reconnected on a new port two minutes later with the conversation continuing normally - demonstrating the error-handling requirement under a real failure, not just the happy path.

## Key Handling - Risk Discussion (required by the brief)

A hardcoded 256-bit key is used in `CryptoUtils` on both sides to make the Python and Dart implementations interoperable for this prototype. This is **not secure for production**: if an attacker gains access to the source code or extracts the compiled app binary, they can retrieve the key and decrypt all captured traffic. A production-ready implementation should either use a key-exchange protocol (such as ECDH) to derive unique session keys per conversation, or store persistent keys in a secure hardware-backed location such as the Android Keystore.

The server also holds this same key, meaning it technically could decrypt traffic if run with `--debug`. This is weaker than true end-to-end encryption between clients only, and is an explicit simplification made to keep the project's scope focused on encryption and socket programming rather than key distribution, which is a separate, harder problem.

## Limitations

- Single hardcoded pre-shared key, as discussed above - no per-session key rotation.
- No user authentication - anyone who connects to the server and has the key can participate.
- Message history exists only for the current app session; nothing is persisted to disk.
- Service/contact names ("Ali", "Sara", etc.) in the Android app are cosmetic placeholders - every contact opens the same underlying connection to the same server.

## Requirements

- Python 3.x with the `cryptography` package
- Flutter/Dart with the `cryptography` pub package

## Author

Tooba - Syntecxhub Cybersecurity Internship, Week 2: Encrypted Chat App.
