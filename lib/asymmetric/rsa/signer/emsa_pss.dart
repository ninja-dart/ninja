import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:ninja/asymmetric/rsa/rsa.dart';
import 'package:ninja/asymmetric/rsa/signer/signer.dart';
import 'package:ninja/padder/mgf/mgf.dart';
import 'package:ninja/utils/big_int.dart';
import 'package:ninja/utils/iterable.dart';
import 'package:ninja/utils/listops.dart';

class RsaSsaPssSigner implements RsaSigner {
  final Mgf mgf;

  final Hash hasher;

  final int saltLength;

  final Random saltGenerator;

  RsaSsaPssSigner(
      {Mgf mgf, Hash hasher, this.saltLength = 0, Random saltGenerator})
      : mgf = mgf ?? mgf1Sha256,
        hasher = hasher ?? sha256,
        saltGenerator = saltGenerator ?? Random.secure();

  List<int> signToBytes(
      RSAPrivateKey key, /* String | List<int> | BigInt */ msg,
      {List<int> salt}) {
    int blockSize = key.blockSize;
    int emBits = key.bitSize - 1;

    List<int> msgBytes;
    if (msg is List<int>) {
      msgBytes = msg;
    } else if (msg is Iterable<int>) {
      msgBytes = msg.toList();
    } else if (msg is String) {
      msgBytes = utf8.encode(msg);
    } else if (msg is BigInt) {
      msgBytes = bigIntToBytes(msg);
    } else {
      throw Exception('invalid message type');
    }

    final mHash = hasher.convert(msgBytes).bytes;
    final hashLength = mHash.length;

    if (emBits < (8 * (hashLength + saltLength) + 9)) {
      throw Exception('emBits too small');
    }

    if (blockSize < hashLength + saltLength + 2) {
      throw Exception('encoding error. blockSize too small');
    }

    if(salt == null) {
      salt =
      List<int>.generate(saltLength, (index) => saltGenerator.nextInt(256));
    } else {
      if(salt.length != saltLength) {
        throw Exception('invalid salt. must be of length $saltLength');
      }
    }

    final mDash = <int>[
      ...List<int>.filled(8, 0),
      ...mHash,
      ...salt,
    ];

    final h = hasher.convert(mDash).bytes;

    final ps = List.filled(blockSize - saltLength - hashLength - 2, 0);

    final db = <int>[
      ...ps,
      0x01,
      ...salt,
    ];

    final dbMask = mgf.encode(blockSize - hashLength - 1, h);

    final maskedDb = ListOps.xor(db, dbMask);

    final em = Uint8List.fromList(<int>[
      ...maskedDb,
      ...h,
      0xbc,
    ]);

    int emDiff = (8 * blockSize) - (emBits);
    if (emDiff < 0) {
      throw Exception();
    } else if (emDiff > 7) {
      throw Exception();
    }
    emDiff = 8 - emDiff;

    em[0] &= (1 << emDiff) - 1;

    return key.engine.signBlock(em);
  }

  String sign(RSAPrivateKey key, /* String | List<int> | BigInt */ msg,
      {List<int> salt}) {
    final bytes = signToBytes(key, msg, salt: salt);
    return base64Encode(bytes);
  }
}

class RsaSsaPssVerifier implements RsaVerifier {
  final Mgf mgf;

  final Hash hasher;

  final int saltLength;

  RsaSsaPssVerifier({Mgf mgf, Hash hasher, this.saltLength = 0})
      : mgf = mgf ?? mgf1Sha256,
        hasher = hasher ?? sha256;

  bool verify(
      RSAPublicKey key,
      /* String | List<int> | BigInt */ signature,
      /* String | List<int> | BigInt */ msg) {
    int emBits = key.bitSize - 1;

    List<int> msgBytes;
    if (msg is List<int>) {
      msgBytes = msg;
    } else if (msg is Iterable<int>) {
      msgBytes = msg.toList();
    } else if (msg is String) {
      msgBytes = utf8.encode(msg);
    } else if (msg is BigInt) {
      msgBytes = bigIntToBytes(msg);
    } else {
      throw Exception('Unknown type');
    }

    final mHash = hasher.convert(msgBytes).bytes;
    final hashLength = mHash.length;

    if (emBits < (8 * (hashLength + saltLength) + 9)) {
      throw Exception('emBits too small');
    }

    final em = key.engine.unsign(signature);

    if (em.length < hashLength + saltLength + 2) {
      throw Exception('inconsistent. encoded message length small');
    }

    if (em.last != 0xbc) {
      throw Exception('inconsistent. bc octet not found in encoded message');
    }

    final maskedDb = em.take(key.blockSize - hashLength - 1);
    final h = em.skip(key.blockSize - hashLength - 1).take(hashLength);

    final dbMask = mgf.encode(maskedDb.length, h);

    final db = ListOps.xor(maskedDb, dbMask);

    int emDiff = (8 * key.blockSize) - (emBits);
    if (emDiff < 0) {
      throw Exception();
    } else if (emDiff > 7) {
      throw Exception();
    }

    db[0] &= (1 << emDiff) - 1;

    final ps = db.take(key.blockSize - hashLength - saltLength - 2);
    if (ps.any((element) => element != 0)) {
      throw Exception('inconsistent. invalid ps');
    }
    if (db.skip(key.blockSize - hashLength - saltLength - 2).first != 0x01) {
      throw Exception('inconsistents');
    }

    final salt = db.skip(key.blockSize - hashLength - saltLength - 1);

    final mDash = <int>[
      ...List<int>.filled(8, 0),
      ...mHash,
      ...salt,
    ];

    final hDash = hasher.convert(mDash).bytes;

    return iterableEquality.equals(h, hDash);
  }

  String extractSalt(
      RSAPublicKey key,
      /* String | List<int> | BigInt */ signature) {
    final hashLength = hasher.convert([0]).bytes.length;

    final em = key.engine.unsign(signature);

    if (em.length < hashLength + saltLength + 2) {
      throw Exception('inconsistent. encoded message length small');
    }

    if (em.last != 0xbc) {
      throw Exception('inconsistent. bc octet not found in encoded message');
    }

    final maskedDb = em.take(key.blockSize - hashLength - 1);
    final h = em.skip(key.blockSize - hashLength - 1).take(hashLength);

    final dbMask = mgf.encode(maskedDb.length, h);

    final db = ListOps.xor(maskedDb, dbMask);

    int emDiff = (8 * key.blockSize) - key.bitSize;
    if (emDiff < 0) {
      throw Exception();
    } else if (emDiff > 7) {
      throw Exception();
    }

    db[0] &= (1 << emDiff) - 1;

    final ps = db.take(key.blockSize - hashLength - saltLength - 2);
    if (ps.any((element) => element != 0)) {
      throw Exception('inconsistent. invalid ps');
    }
    if (db.skip(key.blockSize - hashLength - saltLength - 2).first != 0x01) {
      throw Exception('inconsistent');
    }

    final salt = db.skip(key.blockSize - hashLength - saltLength - 1).toList();

    return base64Encode(salt);
  }
}
