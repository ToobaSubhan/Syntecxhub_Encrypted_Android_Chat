import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:cryptography/cryptography.dart';

// ---------------------- 1. CONFIGURATION ----------------------
class ServerConfig {
  // The phone and server must be on the same network.
  static const String host = '192.168.1.103';
  static const int port = 5000;
}

// ---------------------- 2. CRYPTO UTILS (AES-256-GCM) ----------------------
class CryptoUtils {
  // Pre-shared 256-bit key (must match the server).
  static final List<int> _keyBytes = _hexToBytes(
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  );
  static final SecretKey _secretKey = SecretKey(_keyBytes);
  static final AesGcm _algorithm = AesGcm.with256bits();

  static List<int> _hexToBytes(String hex) {
    final result = <int>[];
    for (var i = 0; i < hex.length; i += 2) {
      result.add(int.parse(hex.substring(i, i + 2), radix: 16));
    }
    return result;
  }

  /// Returns nonce (12) || ciphertext || tag (16). A fresh random nonce is
  /// generated per message by the library.
  static Future<List<int>> encrypt(List<int> plaintext) async {
    final SecretBox secretBox = await _algorithm.encrypt(
      plaintext,
      secretKey: _secretKey,
    );
    return [...secretBox.nonce, ...secretBox.cipherText, ...secretBox.mac.bytes];
  }

  static Future<List<int>> decrypt(List<int> data) async {
    if (data.length < 12 + 16) throw Exception('Invalid ciphertext length');
    final nonce = data.sublist(0, 12);
    final tag = data.sublist(data.length - 16);
    final cipherText = data.sublist(12, data.length - 16);
    final secretBox = SecretBox(cipherText, nonce: nonce, mac: Mac(tag));
    return _algorithm.decrypt(secretBox, secretKey: _secretKey);
  }
}

// ---------------------- 3. TCP CHAT CLIENT ----------------------
class ChatClient {
  Socket? _socket;
  final void Function() onConnected;
  final void Function(String) onMessageReceived;
  final void Function(String) onDisconnected;

  final List<int> _buffer = [];

  ChatClient({
    required this.onConnected,
    required this.onMessageReceived,
    required this.onDisconnected,
  });

  Future<void> connect() async {
    // Close any previous socket first to avoid overlapping connections.
    await disconnect();

    try {
      final socket = await Socket.connect(
        ServerConfig.host,
        ServerConfig.port,
        timeout: const Duration(seconds: 10),
      );

      _socket = socket;
      onConnected();

      socket.listen(
        _handleData,
        onError: (e) {
          if (_socket == socket) onDisconnected('Error: $e');
        },
        onDone: () {
          if (_socket == socket) onDisconnected('Lost Connection');
        },
        cancelOnError: true,
      );
    } catch (_) {
      onDisconnected('Failed: Check IP/Server');
    }
  }

  /// Reassembles length-prefixed frames (4-byte big-endian length + payload).
  void _handleData(List<int> data) {
    _buffer.addAll(data);
    while (_buffer.length >= 4) {
      final header = Uint8List.fromList(_buffer.sublist(0, 4));
      final length = ByteData.view(header.buffer).getUint32(0, Endian.big);

      if (_buffer.length < 4 + length) break;

      final messageData = _buffer.sublist(4, 4 + length);
      _buffer.removeRange(0, 4 + length);
      _processEncryptedMessage(messageData);
    }
  }

  Future<void> _processEncryptedMessage(List<int> data) async {
    try {
      final decrypted = await CryptoUtils.decrypt(data);
      onMessageReceived(utf8.decode(decrypted));
    } catch (_) {
      // Drop messages that fail authentication/decryption.
    }
  }

  Future<void> send(String text) async {
    final socket = _socket;
    if (socket == null) return;
    try {
      final encrypted = await CryptoUtils.encrypt(utf8.encode(text));
      final header = ByteData(4)..setUint32(0, encrypted.length, Endian.big);
      socket.add(header.buffer.asUint8List());
      socket.add(encrypted);
      await socket.flush();
    } catch (_) {
      onDisconnected('Send failed');
    }
  }

  Future<void> disconnect() async {
    final oldSocket = _socket;
    if (oldSocket == null) return;
    _socket = null;
    _buffer.clear();
    try {
      await oldSocket.close();
    } catch (_) {}
    oldSocket.destroy();
  }
}

// ---------------------- 4. UI COMPONENTS ----------------------
void main() => runApp(const MyApp());

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'Encrypted Chat',
      theme: ThemeData(primarySwatch: Colors.teal, useMaterial3: true),
      home: const HomeScreen(),
    );
  }
}

class HomeScreen extends StatelessWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return DefaultTabController(
      length: 3,
      child: Scaffold(
        appBar: AppBar(
          backgroundColor: Colors.teal,
          foregroundColor: Colors.white,
          title: const Text('MyChat'),
          bottom: const TabBar(
            labelColor: Colors.white,
            unselectedLabelColor: Colors.white70,
            indicatorColor: Colors.white,
            tabs: [
              Tab(text: 'CHATS'),
              Tab(text: 'STATUS'),
              Tab(text: 'CALLS'),
            ],
          ),
        ),
        body: const TabBarView(
          children: [
            ChatsScreen(),
            StatusScreen(),
            CallsScreen(),
          ],
        ),
      ),
    );
  }
}

class ChatsScreen extends StatelessWidget {
  const ChatsScreen({super.key});

  static const _contacts = [
    ('Ali', Colors.teal),
    ('Sara', Colors.orange),
    ('Ahmed', Colors.purple),
    ('Fatima', Colors.blue),
  ];

  @override
  Widget build(BuildContext context) {
    return ListView.builder(
      itemCount: _contacts.length,
      itemBuilder: (context, index) {
        final (name, color) = _contacts[index];
        return ListTile(
          onTap: () => Navigator.push(
            context,
            MaterialPageRoute(builder: (_) => ChatScreen(title: name)),
          ),
          leading: CircleAvatar(
            backgroundColor: color,
            child: Text(name[0], style: const TextStyle(color: Colors.white)),
          ),
          title: Text(name),
          subtitle: const Text('AES-256-GCM Secure Chat'),
        );
      },
    );
  }
}

class Message {
  final String text;
  final bool isMe;
  const Message(this.text, this.isMe);
}

class ChatScreen extends StatefulWidget {
  final String title;
  const ChatScreen({super.key, required this.title});

  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  final TextEditingController _controller = TextEditingController();
  final List<Message> _messages = [];
  late final ChatClient _client;
  String _status = 'Connecting...';

  @override
  void initState() {
    super.initState();
    _client = ChatClient(
      onConnected: () => _setStatus('Secure Channel Active'),
      onMessageReceived: (text) {
        if (mounted) setState(() => _messages.add(Message(text, false)));
      },
      onDisconnected: _setStatus,
    );
    _connect();
  }

  void _setStatus(String status) {
    if (mounted) setState(() => _status = status);
  }

  void _connect() {
    _setStatus('Connecting...');
    _client.connect();
  }

  @override
  void dispose() {
    _client.disconnect();
    _controller.dispose();
    super.dispose();
  }

  void _sendMessage() {
    final text = _controller.text.trim();
    if (text.isEmpty) return;
    _client.send(text);
    setState(() {
      _messages.add(Message(text, true));
      _controller.clear();
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Colors.teal,
        foregroundColor: Colors.white,
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(widget.title),
            Text(_status, style: const TextStyle(fontSize: 10, color: Colors.white70)),
          ],
        ),
        actions: [
          IconButton(icon: const Icon(Icons.refresh), onPressed: _connect),
        ],
      ),
      body: SafeArea(
        child: Column(
          children: [
            Expanded(
              child: ListView.builder(
                padding: const EdgeInsets.all(10),
                itemCount: _messages.length,
                itemBuilder: (context, index) {
                  final msg = _messages[index];
                  return Align(
                    alignment: msg.isMe ? Alignment.centerRight : Alignment.centerLeft,
                    child: Container(
                      margin: const EdgeInsets.symmetric(vertical: 4),
                      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                      decoration: BoxDecoration(
                        color: msg.isMe ? Colors.teal[100] : Colors.grey[300],
                        borderRadius: BorderRadius.circular(15),
                      ),
                      child: Text(msg.text),
                    ),
                  );
                },
              ),
            ),
            Padding(
              padding: const EdgeInsets.all(8.0),
              child: Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: _controller,
                      onSubmitted: (_) => _sendMessage(),
                      decoration: const InputDecoration(
                        hintText: 'Type encrypted message...',
                        border: OutlineInputBorder(),
                      ),
                    ),
                  ),
                  IconButton(
                    icon: const Icon(Icons.send, color: Colors.teal),
                    onPressed: _sendMessage,
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class StatusScreen extends StatelessWidget {
  const StatusScreen({super.key});

  @override
  Widget build(BuildContext context) =>
      const Center(child: Text('Status updates are private.'));
}

class CallsScreen extends StatelessWidget {
  const CallsScreen({super.key});

  @override
  Widget build(BuildContext context) =>
      const Center(child: Text('Calls history is empty.'));
}