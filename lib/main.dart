import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:cryptography/cryptography.dart';

// ---------------------- 1. CONFIGURATION ----------------------
class ServerConfig {
  // Set this to the server machine's IPv4 address (run `ipconfig` on Windows).
  // The phone and server must be on the same network.
  static const String host = '192.168.1.104';
  static const int port = 5000;
}

// ---------------------- 2. SECURE STORAGE ----------------------
/// Thin wrapper over Android Keystore-backed storage.
class SecureStore {
  static const FlutterSecureStorage _storage = FlutterSecureStorage();

  static Future<String?> read(String key) => _storage.read(key: key);
  static Future<void> write(String key, String value) =>
      _storage.write(key: key, value: value);
  static Future<void> deleteAll() => _storage.deleteAll();
}

// ---------------------- 3. CRYPTO UTILS (AES-256-GCM) ----------------------
class CryptoUtils {
  static const String _keyName = 'aes_key_hex';
  static final AesGcm _algorithm = AesGcm.with256bits();
  static SecretKey? _secretKey;

  static bool get hasKey => _secretKey != null;

  static bool isValidKey(String hex) =>
      RegExp(r'^[0-9a-fA-F]{64}$').hasMatch(hex);

  /// Loads the pre-shared key from secure storage (if one was saved).
  static Future<void> init() async {
    final hex = await SecureStore.read(_keyName);
    if (hex != null && isValidKey(hex)) {
      _secretKey = SecretKey(_hexToBytes(hex));
    }
  }

  static Future<void> saveKey(String hex) async {
    await SecureStore.write(_keyName, hex);
    _secretKey = SecretKey(_hexToBytes(hex));
  }

  /// Removes the key and all stored chat history.
  static Future<void> resetAll() async {
    await SecureStore.deleteAll();
    _secretKey = null;
  }

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
    final key = _secretKey;
    if (key == null) throw StateError('No key set');
    final SecretBox box = await _algorithm.encrypt(plaintext, secretKey: key);
    return [...box.nonce, ...box.cipherText, ...box.mac.bytes];
  }

  static Future<List<int>> decrypt(List<int> data) async {
    final key = _secretKey;
    if (key == null) throw StateError('No key set');
    if (data.length < 12 + 16) throw Exception('Invalid ciphertext length');
    final nonce = data.sublist(0, 12);
    final tag = data.sublist(data.length - 16);
    final cipherText = data.sublist(12, data.length - 16);
    final box = SecretBox(cipherText, nonce: nonce, mac: Mac(tag));
    return _algorithm.decrypt(box, secretKey: key);
  }
}

// ---------------------- 4. MESSAGE MODEL + HISTORY ----------------------
class Message {
  final String text;
  final bool isMe;
  const Message(this.text, this.isMe);

  Map<String, dynamic> toJson() => {'t': text, 'm': isMe};
  factory Message.fromJson(Map<String, dynamic> json) =>
      Message(json['t'] as String, json['m'] as bool);
}

/// Per-contact chat history, kept in Keystore-backed secure storage.
class HistoryStore {
  static const int _maxMessages = 200;
  static String _key(String contact) => 'history_$contact';

  static Future<List<Message>> load(String contact) async {
    try {
      final raw = await SecureStore.read(_key(contact));
      if (raw == null) return [];
      return (jsonDecode(raw) as List)
          .map((e) => Message.fromJson(e as Map<String, dynamic>))
          .toList();
    } catch (_) {
      return [];
    }
  }

  static Future<void> save(String contact, List<Message> messages) async {
    final recent = messages.length > _maxMessages
        ? messages.sublist(messages.length - _maxMessages)
        : messages;
    try {
      await SecureStore.write(
        _key(contact),
        jsonEncode(recent.map((m) => m.toJson()).toList()),
      );
    } catch (_) {}
  }
}

// ---------------------- 5. TCP CHAT CLIENT ----------------------
class ChatClient {
  Socket? _socket;
  final void Function() onConnected;
  final void Function(String) onMessageReceived;
  final void Function(String) onDisconnected;
  final void Function(String)? onError;

  final List<int> _buffer = [];

  ChatClient({
    required this.onConnected,
    required this.onMessageReceived,
    required this.onDisconnected,
    this.onError,
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
      // Authentication failed: wrong key or tampered message. Drop it.
      onError?.call('Decryption failed: check key');
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

// ---------------------- 6. UI COMPONENTS ----------------------
Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await CryptoUtils.init();
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  bool _hasKey = CryptoUtils.hasKey;

  Future<void> _reset() async {
    await CryptoUtils.resetAll();
    if (mounted) setState(() => _hasKey = false);
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'Encrypted Chat',
      theme: ThemeData(primarySwatch: Colors.teal, useMaterial3: true),
      home: _hasKey
          ? HomeScreen(onReset: _reset)
          : KeySetupScreen(onSaved: () => setState(() => _hasKey = true)),
    );
  }
}

/// Shown on first launch (or after a reset): the shared key is entered once
/// and stored in the Android Keystore, never in source code.
class KeySetupScreen extends StatefulWidget {
  final VoidCallback onSaved;
  const KeySetupScreen({super.key, required this.onSaved});

  @override
  State<KeySetupScreen> createState() => _KeySetupScreenState();
}

class _KeySetupScreenState extends State<KeySetupScreen> {
  final TextEditingController _controller = TextEditingController();
  String? _error;
  bool _obscure = true;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    final hex = _controller.text.trim().toLowerCase();
    if (!CryptoUtils.isValidKey(hex)) {
      setState(() => _error = 'Key must be 64 hex characters (256-bit).');
      return;
    }
    await CryptoUtils.saveKey(hex);
    widget.onSaved();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Colors.teal,
        foregroundColor: Colors.white,
        title: const Text('Set Encryption Key'),
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Text(
                'Enter the 256-bit shared key (64 hex characters) used by the '
                    'server. It is stored in the Android Keystore.',
              ),
              const SizedBox(height: 16),
              TextField(
                controller: _controller,
                obscureText: _obscure,
                autocorrect: false,
                enableSuggestions: false,
                decoration: InputDecoration(
                  labelText: 'Shared key (hex)',
                  border: const OutlineInputBorder(),
                  errorText: _error,
                  suffixIcon: IconButton(
                    icon: Icon(_obscure ? Icons.visibility : Icons.visibility_off),
                    onPressed: () => setState(() => _obscure = !_obscure),
                  ),
                ),
                onSubmitted: (_) => _save(),
              ),
              const SizedBox(height: 16),
              FilledButton(onPressed: _save, child: const Text('Save key')),
            ],
          ),
        ),
      ),
    );
  }
}

class HomeScreen extends StatelessWidget {
  final VoidCallback onReset;
  const HomeScreen({super.key, required this.onReset});

  @override
  Widget build(BuildContext context) {
    return DefaultTabController(
      length: 3,
      child: Scaffold(
        appBar: AppBar(
          backgroundColor: Colors.teal,
          foregroundColor: Colors.white,
          title: const Text('MyChat'),
          actions: [
            PopupMenuButton<String>(
              onSelected: (_) => onReset(),
              itemBuilder: (_) => const [
                PopupMenuItem(value: 'reset', child: Text('Reset key & history')),
              ],
            ),
          ],
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
  bool _historyLoaded = false;

  @override
  void initState() {
    super.initState();
    _client = ChatClient(
      onConnected: () => _setStatus('Secure Channel Active'),
      onMessageReceived: (text) {
        if (!mounted) return;
        setState(() => _messages.add(Message(text, false)));
        _persist();
      },
      onDisconnected: _setStatus,
      onError: _setStatus,
    );
    _loadHistory();
    _connect();
  }

  Future<void> _loadHistory() async {
    final saved = await HistoryStore.load(widget.title);
    if (!mounted) return;
    setState(() {
      _messages.insertAll(0, saved);
      _historyLoaded = true;
    });
    _persist();
  }

  // Saves only after the stored history has been loaded, so it is never
  // overwritten by messages that arrived first.
  void _persist() {
    if (_historyLoaded) HistoryStore.save(widget.title, _messages);
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
    _persist();
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