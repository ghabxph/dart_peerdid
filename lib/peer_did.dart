import 'package:fast_base58/fast_base58.dart';
import 'package:peerdid/private_key.dart';
import 'package:peerdid/public_key.dart';
import 'package:crypto/crypto.dart';
import 'package:uuid/uuid.dart';
import 'dart:convert';

class PeerDID {
  final String __registerUuid = Uuid().v4();
  final String __adminUuid = Uuid().v4();
  List<Map> __publicKey;

  /// PeerDID Constructor
  ///   - This constructor is unavailable. Use PeerDID.create() instead
  PeerDID._constructor();

  static PeerDID create(List<Map> publicKey) {
    final instance = PeerDID._constructor();
    return instance._dd(publicKey);
  }

  PeerDID _dd(List<Map> publicKey) {
    var qq = [
      {
        'key': 'k',
        'roles': ['register']
      }
    ];
  }
}

class GenesisPeerDID {

  PrivateKey __register;
  PrivateKey __admin;
  PrivateKey __authentication;
  final String __registerUuid = Uuid().v4();
  final String __adminUuid = Uuid().v4();

  /// GenesisPeerDID Constructor
  ///   - This constructor is unavailable. Use GenesisPeerDID.create() instead.
  GenesisPeerDID._constructor();

  static Future<GenesisPeerDID> create({PrivateKey register: null, PrivateKey admin: null, PrivateKey authentication: null}) async {
    final instance = GenesisPeerDID._constructor();
    instance.__register = register ?? await Ed25519Seed.create();
    instance.__admin = admin ?? await Ed25519Seed.create();
    instance.__authentication = authentication ?? await Ed25519Seed.create();
    return instance;
  }

  /// Returns the base58 public/private keys for register, admin, and authentication
  Map get keys => {
    'register': {
      'public': __register.publicKey.publicKeyBase58,
      'private': __register.privateKeyBase58
    },
    'admin': {
      'public': __admin.publicKey.publicKeyBase58,
      'private': __admin.privateKeyBase58
    },
    'authentication': {
      'public': __authentication.publicKey.publicKeyBase58,
      'private': __authentication.privateKeyBase58
    }
  };

  List<Map> get _publicKey => [
    _getPublicKey(__register),
    _getPublicKey(__admin),
    _getPublicKey(__authentication),
  ];

  List<String> get _authentication => [__authentication.publicKey.hid];

  Map get _authorization => { 'profiles': _profiles, 'rules': _rules };

  List<Map> get _profiles => [
    { 'key': __register.publicKey.hid, 'roles': ['register'] },
    { 'key': __admin.publicKey.hid, 'roles': ['admin'] },
    { 'key': __authentication.publicKey.hid, 'roles': ['auth'] },
  ];

  List<Map> get _rules => [
    {
      'grant': ['register'],
      'when': { 'roles': 'register' },
      'id': __registerUuid
    },
    {
      'grant': ['key_admin', 'se_admin', 'rule_admin'],
      'when': { 'roles': 'admin' },
      'id': __adminUuid
    }
  ];

  Map _getPublicKey(PrivateKey pk) => {
    'id': pk.publicKey.id,
    'type': pk.publicKey.type,
    'controller': pk.publicKey.controller,
    'publicKeyBase58': pk.publicKey.publicKeyBase58
  };

  /// Signs the base58 encoded DID document that is to be used
  /// for registering DID to target entity.
  Future<String> get register async => '${encodedDoc}.${await __register.sign(encodedDoc)}';

  /// Returns PeerDID URI
  String get uri => 'did:peer:1z${Base58Encode(<int>[0x12,0x20] + sha256.convert(utf8.encode(doc)).bytes)}';

  /// Returns Base58 Encoded DID Document
  String get encodedDoc => Base58Encode(utf8.encode(doc));

  /// Returns DID Document of this PeerDID
  String get doc => json.encode({
    'publicKey': _publicKey,
    'authentication': _authentication,
    'authorization': _authorization
  });

  /// Returns the DID
  @override
  String toString() => uri;
}

class GenesisPeerDIDVerify {

  Map _didDoc;
  String _base58Signature;

  GenesisPeerDIDVerify(String signedDoc) {
    final _signedDoc = signedDoc.split('.');
    _didDoc = json.decode(utf8.decode(Base58Decode(_signedDoc[0])));
    _base58Signature = _signedDoc[1];
  }
}

/// Verifies signed genesis doc using register public key
bool genesisPeerDIDVerifyRegister(String signedDoc) {
  final _signedDoc = signedDoc.split('.');
  final didDoc = json.decode(utf8.decode(Base58Decode(_signedDoc[0])));
  print(didDoc);
  return false;
}
