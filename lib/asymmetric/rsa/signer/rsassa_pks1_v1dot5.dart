import 'dart:convert';

import 'package:ninja/asymmetric/rsa/encoder/emsaPkcs1V1dot5.dart';
import 'package:ninja/asymmetric/rsa/engine/decrypter.dart';
import 'package:ninja/asymmetric/rsa/engine/encrypter.dart';
import 'package:ninja/asymmetric/rsa/rsa.dart';
import 'package:ninja/ninja.dart';
import 'package:ninja/utils/big_int.dart';
import 'package:ninja/utils/iterable.dart';

abstract class Signer {
  List<int> signToBytes(/* String | List<int> | BigInt */ msg);

  String sign(/* String | List<int> | BigInt */ msg);
}

abstract class Verifier {
  bool verify(
      /* String | List<int> | BigInt */ signature,
      /* String | List<int> | BigInt */ msg);
}

class RsassaPkcs1V1dot5Signer implements Signer {
  final RSAPrivateKey key;

  final EmsaHasher hasher;

  final RSADecryptionEngine engine;

  RsassaPkcs1V1dot5Signer(this.key, {EmsaHasher hasher})
      : hasher = hasher ?? EmsaHasher.sha256,
        engine = RSADecryptionEngine(key);

  List<int> signToBytes(final /* String | List<int> | BigInt */ msg) {
    List<int> msgBytes;
    if(msg is List<int>) {
      msgBytes = msg;
    } else if (msg is String) {
      msgBytes = utf8.encode(msg);
    } else if (msg is BigInt) {
      msgBytes = bigIntToBytes(msg);
    }

    final encodedMessage =
        emsaPkcs1V1dot5Encode(msgBytes, engine.blockSize, hasher);

    return engine.signBlock(encodedMessage);
  }

  String sign(/* String | List<int> | BigInt */ msg) {
    final bytes = signToBytes(msg);
    return base64Encode(bytes);
  }
}

class RsassaPkcs1V1dot5Verifier implements Verifier {
  final RSAPublicKey key;

  final EmsaHasher hasher;

  final RSAEncryptionEngine engine;

  RsassaPkcs1V1dot5Verifier(this.key, {EmsaHasher hasher})
      : hasher = hasher ?? EmsaHasher.sha256,
        engine = RSAEncryptionEngine(key);

  bool verify(/* String | List<int> | BigInt */ signature,
      final /* String | List<int> | BigInt */ msg) {
    final emDash = engine.unsign(signature);

    List<int> msgBytes;
    if (msg is List<int>) {
      msgBytes = msg;
    } else if (msg is String) {
      msgBytes = utf8.encode(msg);
    } else if (msg is BigInt) {
      msgBytes = bigIntToBytes(msg);
    } else {
      throw Exception('Unknown type');
    }
    final encodedMessage =
        emsaPkcs1V1dot5Encode(msgBytes, engine.blockSize, hasher);

    return iterableEquality.equals(emDash, encodedMessage);
  }
}
