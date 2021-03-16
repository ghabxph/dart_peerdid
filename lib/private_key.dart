import 'package:cryptography/cryptography.dart' as c;
import 'package:fast_base58/fast_base58.dart';
import 'package:peerdid/public_key.dart';

abstract class PrivateKey {

  /// Returns PublicKey instance
  PublicKey get publicKey;
  String get privateKeyBase58;
  Future<String> sign(String base58Message);
}

class Ed25519Seed extends PrivateKey {

  c.KeyPair _keyPair;

  PublicKey _publicKey;

  /// Ed25519Seed Constructor
  ///   - This constructor is unavailable. Use Ed25519Seed.create() instead.
  Ed25519Seed._constructor();

  /// Create Ed25519Seed instance from private key bytes
  static Future<Ed25519Seed> create([String base58Seed]) async {
    final instance = Ed25519Seed._constructor();
    return await instance._setKeyPair(base58Seed);
  }

  /// Create Ed25519Seed instance from base58 encoded Ed25519 private key
  Future<Ed25519Seed> _setKeyPair([String base58Seed]) async {
    _keyPair = base58Seed == null ? await c.ed25519.newKeyPair() : await c.ed25519.newKeyPairFromSeed(c.PrivateKey(Base58Decode(base58Seed)));
    _publicKey = Ed25519PublicKey.createFromBytes(_keyPair.publicKey.bytes);
    return this;
  }

  /// Returns Ed25519PublicKey instance
  @override
  PublicKey get publicKey => _publicKey;

  @override
  String get privateKeyBase58 => Base58Encode(_keyPair.privateKey.extractSync());

  @override
  Future<String> sign(String base58Message) async => Base58Encode((await c.ed25519.sign(Base58Decode(base58Message), _keyPair)).bytes);
}
