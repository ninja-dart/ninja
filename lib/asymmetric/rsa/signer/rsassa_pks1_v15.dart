import 'dart:convert';

import 'package:ninja/asymmetric/rsa/encoder/emsaPkcs1V15.dart';
import 'package:ninja/asymmetric/rsa/rsa.dart';
import 'package:ninja/asymmetric/rsa/signer/signer.dart';
import 'package:ninja/ninja.dart';
import 'package:ninja/utils/big_int.dart';
import 'package:ninja/utils/iterable.dart';

class RsassaPkcs1V15Signer implements RsaSigner {
  final EmsaHasher hasher;

  RsassaPkcs1V15Signer({EmsaHasher hasher})
      : hasher = hasher ?? EmsaHasher.sha256;

  List<int> signToBytes(
      final RSAPrivateKey key, final /* String | List<int> | BigInt */ msg) {
    List<int> msgBytes;
    if (msg is List<int>) {
      msgBytes = msg;
    } else if (msg is String) {
      msgBytes = utf8.encode(msg);
    } else if (msg is BigInt) {
      msgBytes = bigIntToBytes(msg);
    }

    final encodedMessage = emsaPkcs1V15Encode(msgBytes, key.blockSize, hasher);

    return key.engine.signBlock(encodedMessage);
  }

  String sign(RSAPrivateKey key, /* String | List<int> | BigInt */ msg) {
    final bytes = signToBytes(key, msg);
    return base64Encode(bytes);
  }
}

class RsassaPkcs1V15Verifier implements RsaVerifier {
  final EmsaHasher hasher;

  RsassaPkcs1V15Verifier({EmsaHasher hasher})
      : hasher = hasher ?? EmsaHasher.sha256;

  bool verify(RSAPublicKey key, /* String | List<int> | BigInt */ signature,
      final /* String | List<int> | BigInt */ msg) {
    final emDash = key.engine.unsign(signature);

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
    final encodedMessage = emsaPkcs1V15Encode(msgBytes, key.blockSize, hasher);

    return iterableEquality.equals(emDash, encodedMessage);
  }
}
