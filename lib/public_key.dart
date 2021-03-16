import 'package:cryptography/cryptography.dart' as c;
import 'package:fast_base58/fast_base58.dart';

abstract class PublicKey {
  String get id;
  String get hid;
  String get type;
  String get controller => '#id';
  String get publicKeyBase58;
  Future<bool> verify(String base58Message, String base58Signature);
}

class Ed25519PublicKey extends PublicKey {

  c.PublicKey _publicKey;

  /// Ed25519Seed Constructor
  ///   - This constructor is unavailable. Use Ed25519Seed.create() instead
  Ed25519PublicKey._constructor();

  /// Create Ed25519PublicKey instance from public key bytes
  static Ed25519PublicKey createFromBytes(List<int> bytes) {
    final instance = Ed25519PublicKey._constructor();
    instance._publicKey = c.PublicKey(bytes);
    return instance;
  }

  /// Create Ed25519PublicKey instance from base58 encoded Ed25519 public key
  static Ed25519PublicKey createFromBase58EncodedPublicKey(String base58PublicKey) {
    final instance = Ed25519PublicKey._constructor();
    instance._publicKey = c.PublicKey(Base58Decode(base58PublicKey));
    return instance;
  }

  @override
  String get id => publicKeyBase58.substring(0, 7);

  @override
  String get hid => '#$id';

  @override
  String get publicKeyBase58 => Base58Encode(_publicKey.bytes);

  @override
  String get type => 'Ed25519VerificationKey2018';

  @override
  Future<bool> verify(String base58Message, String base58Signature) async => await c.ed25519.verify(Base58Decode(base58Message), c.Signature(Base58Decode(base58Signature), publicKey: _publicKey));
}
