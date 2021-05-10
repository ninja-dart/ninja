import 'dart:convert';

import 'package:ninja/asymmetric/rsa/encoder/emsaPkcs1v15.dart';
import 'package:ninja/asymmetric/rsa/rsa.dart';
import 'package:ninja/asymmetric/rsa/signer/signer.dart';
import 'package:ninja/ninja.dart';
import 'package:ninja/utils/big_int.dart';
import 'package:ninja/utils/iterable.dart';

class RsassaPkcs1v15Signer implements RsaSigner {
  final EmsaHasher hasher;

  RsassaPkcs1v15Signer({EmsaHasher? hasher})
      : hasher = hasher ?? EmsaHasher.sha256;

  List<int> sign(
      final RSAPrivateKey key, final /* String | List<int> | BigInt */ msg) {
    List<int> msgBytes;
    if (msg is List<int>) {
      msgBytes = msg;
    } else if (msg is String) {
      msgBytes = utf8.encode(msg);
    } else if (msg is BigInt) {
      msgBytes = bigIntToBytes(msg);
    } else {
      throw ArgumentError.notNull('msg');
    }

    final encodedMessage = emsaPkcs1v15Encode(msgBytes, key.blockSize, hasher);

    return key.engine.signBlock(encodedMessage);
  }

  String signToBase64(
      RSAPrivateKey key, /* String | List<int> | BigInt */ msg) {
    final bytes = sign(key, msg);
    return base64Encode(bytes);
  }
}

class RsassaPkcs1v15Verifier implements RsaVerifier {
  final EmsaHasher hasher;

  RsassaPkcs1v15Verifier({EmsaHasher? hasher})
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
    final encodedMessage = emsaPkcs1v15Encode(msgBytes, key.blockSize, hasher);

    return iterableEquality.equals(emDash, encodedMessage);
  }
}
