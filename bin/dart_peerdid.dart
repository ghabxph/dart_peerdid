import 'dart:convert';

import 'package:fast_base58/fast_base58.dart';
import 'package:peerdid/peer_did.dart';
import 'package:peerdid/private_key.dart';
import 'package:cryptography/cryptography.dart' as c;
import 'package:crypto/crypto.dart';
import 'package:peerdid/peer_did_components.dart';

Future<void> main() async {

  final did = await GenesisPeerDID.create(
    register: await Ed25519Seed.create('8PDZgG8xK1XtLVpBUC7JxhyGtuVS8KgNxUXE2y4WWALp'),
    admin: await Ed25519Seed.create('nGNtty3oQxmjukfftAPAhUnGs8yrz9dbKukArakR38h'),
    authentication: await Ed25519Seed.create('AeR4DPtwQH87aMuYFGZ3gZgdQEbihMTnvef9Ux2WuXZq')
  );

  print(did);
  print(did.doc);
  print('Register public: ${did.keys["register"]["public"]}');
  print('Register private: ${did.keys["register"]["private"]}');
  print('Admin public: ${did.keys["admin"]["public"]}');
  print('Admin private: ${did.keys["admin"]["private"]}');
  print('Authentication public: ${did.keys["authentication"]["public"]}');
  print('Authentication private: ${did.keys["authentication"]["private"]}');

  final signedDoc = await did.register;
  print(signedDoc);
  print(genesisPeerDIDVerifyRegister(signedDoc));

  print(PrivilegeInventory.register.toString());

  //print(key.keyPair);
  //print(did.toString());
  //print('Hello world');
}
/*Future<void> main() async {
  / The message that we will sign
  //final message = <int>[1,2,3];
  final message = "Ang aking pinaka importanteng pinal na mensahe sa ikapapalagay ng sangkatauhan".codeUnits;

  //final pkey = <int>[119, 213, 10, 158, 33, 158, 210, 63, 33, 240, 88, 58, 253, 253, 62, 216, 77, 253, 244, 114, 16, 214, 13, 238, 240, 151, 87, 49, 178, 152, 76, 13];

  final pkey = Base58Decode('H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV');

  var seed = PrivateKey(pkey);

  final keyPair = await ed25519.newKeyPairFromSeed(seed);

  // Generate a random ED25519 keypair
  //final keyPair = await ed25519.newKeyPair();

  // Sign
  final signature = await ed25519.sign(
    message,
    keyPair,
  );

  print('Private key: ${keyPair.privateKey.extractSync().toString()}');

  print('Signature: ${signature.bytes}');
  print('Public key: ${signature.publicKey.bytes}');

  // Verify signature
  final isSignatureCorrect = await ed25519.verify(
    message,
    signature,
  );

  print('Is the signature correct: $isSignatureCorrect');
}*/
