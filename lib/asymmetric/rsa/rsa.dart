import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:ninja/asymmetric/rsa/engine/decrypter.dart';
import 'package:ninja/asymmetric/rsa/engine/encrypter.dart';
import 'package:ninja/ninja.dart';
import 'package:ninja/utils/big_int.dart';
import 'package:ninja/utils/hex_string.dart';

/// Public key for RSA encryption
class RSAPublicKey {
  RSAPublicKey(this.n, this.e) {
    _engine = RSAEncryptionEngine(this);
  }

  // TODO better exceptions
  factory RSAPublicKey.fromASN1(String input) {
    final asn1 = ASN1Parser(base64.decode(input));
    if (!asn1.hasNext()) {
      throw Exception("Invalid structure");
    }
    final root = asn1.nextObject();
    if (root is! ASN1Sequence) throw Exception('Invalid structure');

    final rootChildren = (root as ASN1Sequence).elements;
    if (rootChildren.length != 2) throw Exception('Invalid structure');
    if (rootChildren.first is! ASN1Sequence) {
      throw Exception('Invalid structure');
    } else {
      final objSequence = rootChildren.first as ASN1Sequence;
      if (objSequence.elements.isEmpty) {
        throw Exception('Invalid structure');
      }

      if (objSequence.elements.first is! ASN1ObjectIdentifier) {
        throw Exception('Invalid input');
      } else {
        final identifier =
            (objSequence.elements.first as ASN1ObjectIdentifier).identifier;
        if (identifier != '1.2.840.113549.1.1.1') {
          throw Exception('Invalid identifier');
        }
      }
    }

    if (rootChildren[1] is! ASN1BitString) {
      throw Exception('Invalid structure');
    }

    final inner = ASN1Sequence.fromBytes(
        (rootChildren[1] as ASN1BitString).contentBytes());
    if (inner.elements.length != 2) {
      throw Exception('Invalid structure');
    }

    if (inner.elements.any((e) => e is! ASN1Integer)) {
      throw Exception('Invalid structure');
    }

    final numbers = inner.elements
        .map<BigInt>((e) => bytesToBigInt((e as ASN1Integer).valueBytes()))
        .toList();

    return RSAPublicKey(numbers[0], numbers[1]);
  }

  factory RSAPublicKey.fromPEM(String input) {
    // TODO
  }

  /// Modulus
  final BigInt n;

  /// Public exponent
  final BigInt e;

  RSAEncryptionEngine _engine;

  RSAEncryptionEngine get engine => _engine;

  int get blockSize => engine.blockSize;

  Iterable<int> encryptToBytes(/* String | Iterable<int> */ input,
      {BlockPadder padder}) {
    Iterable<int> inputBytes;
    if (input is String) {
      inputBytes = utf8.encode(input);
    } else if (input is Iterable<int>) {
      inputBytes = input;
    } else {
      throw ArgumentError('Should be String or List<int>');
    }
    if (padder != null) {
      inputBytes = padder.pad(blockSize, inputBytes);
    }
    return engine.process(inputBytes);
  }

  String encrypt(/* String | Iterable<int> */ input, {BlockPadder padder}) {
    return hexEncoder.convert(encryptToBytes(input, padder: padder));
  }

  String encryptToBase64(/* String | Iterable<int> */ input,
      {BlockPadder padder}) {
    return base64Encode(encryptToBytes(input, padder: padder));
  }

  Iterable<int> encryptPkcsToBytes(/* String | Iterable<int> */ input,
      {Random rand}) {
    return encryptToBytes(input, padder: EmePkcs1V15Encoder(rand: rand));
  }

  String encryptPkcs(/* String | Iterable<int> */ input, {Random rand}) {
    return encrypt(input, padder: EmePkcs1V15Encoder(rand: rand));
  }

  String encryptPkcsToBase64(/* String | Iterable<int> */ input,
      {Random rand}) {
    return encryptToBase64(input, padder: EmePkcs1V15Encoder(rand: rand));
  }

  Iterable<int> encryptOaepToBytes(
      /* String | Iterable<int> */ input, OAEPPadder oaepPadder) {
    return encryptToBytes(input, padder: oaepPadder);
  }

  String encryptOaep(
      /* String | Iterable<int> */ input, OAEPPadder oaepPadder) {
    return encrypt(input, padder: oaepPadder);
  }

  String encryptOaepToBase64(
      /* String | Iterable<int> */ input, OAEPPadder oaepPadder) {
    return encryptToBase64(input, padder: oaepPadder);
  }

  // TODO verify

  String toString() => 'RSAPublicKey(n: $n, e: $e)';
}

/// Private key for RSA encryption
class RSAPrivateKey {
  RSAPrivateKey(this.n, this.e, this.d, this.p, this.q) {
    _engine = RSADecryptionEngine(this);
  }

  factory RSAPrivateKey.generate() {
    // TODO
  }

  factory RSAPrivateKey.fromASN1(String input) {
    final p = ASN1Parser(base64.decode(input));
    if (!p.hasNext()) throw Exception('Invalid structure');
    final rootSequence = p.nextObject();
    if (rootSequence is! ASN1Sequence) {
      throw Exception('Invalid structure');
    }

    {
      final pcks8 = _isPkcs8(rootSequence);
      if (pcks8 != null) {
        return _fromASN1Sequence(pcks8);
      }
    }

    return _fromASN1Sequence(rootSequence);
  }

  factory RSAPrivateKey.fromPEM(String input) {
    // TODO
  }

  static RSAPrivateKey _fromASN1Sequence(ASN1Sequence rootSequence) {
    final rootChildren = rootSequence.elements;
    if (rootChildren.length < 6) {
      throw Exception('Invalid structure');
    }

    final relevant = rootChildren.skip(1).take(5);
    if (relevant.any((e) => e is! ASN1Integer)) {
      throw Exception('Invalid structure');
    }

    final bigInts = relevant
        .map((e) => bytesToBigInt((e as ASN1Integer).valueBytes()))
        .toList();
    return RSAPrivateKey(
        bigInts[0], bigInts[1], bigInts[2], bigInts[3], bigInts[4]);
  }

  static ASN1Sequence _isPkcs8(ASN1Sequence rootSequence) {
    if (rootSequence.elements.length != 3) return null;

    if (rootSequence.elements[1] is! ASN1Sequence) return null;

    if (!_checkObjectId(rootSequence.elements[1], "1.2.840.113549.1.1.1")) {
      return null;
    }

    if (rootSequence.elements[2] is! ASN1OctetString) {
      throw Exception("Invalid structure");
    }

    final sequence = ASN1Sequence.fromBytes(
        (rootSequence.elements[2] as ASN1OctetString).valueBytes());

    return sequence;
  }

  /// Modulus
  final BigInt n;

  /// Public exponent
  final BigInt e;

  /// Private exponent
  final BigInt d;

  /// Prime p
  final BigInt p;

  /// Prime q
  final BigInt q;

  RSADecryptionEngine _engine;

  RSADecryptionEngine get engine => _engine;

  int get blockSize => engine.blockSize;

  Iterable<int> decryptToBytes(/* String | List<int> */ input,
      {BlockPadder padder, bool raw = false}) {
    Uint8List inputBytes;
    if (input is String) {
      inputBytes = hexDecoder.convert(input);
    } else if (input is Uint8List) {
      inputBytes = input;
    } else if (input is List<int>) {
      inputBytes = Uint8List.fromList(input);
    } else {
      throw ArgumentError('Should be String or List<int>');
    }
    Uint8List unpadded = engine.process(inputBytes, dontPadLastBlock: raw);
    if (padder == null) {
      return unpadded;
    }
    return padder.unpad(blockSize, unpadded);
  }

  String decrypt(/* String | List<int> */ input,
      {BlockPadder padder, bool raw = false}) {
    return utf8.decode(
        decryptToBytes(input, padder: padder, raw: raw));
  }

  Iterable<int> decryptPkcsToBytes(/* String | List<int> */ input) {
    return decryptToBytes(input, padder: EmePkcs1V15Encoder());
  }

  String decryptPkcs(/* String | List<int> */ input) {
    return decrypt(input, padder: EmePkcs1V15Encoder());
  }

  Iterable<int> decryptOaepToBytes(/* String | List<int> */ input, OAEPPadder oaepPadder) {
    return decryptToBytes(input, padder: oaepPadder);
  }

  String decryptOaep(/* String | List<int> */ input, OAEPPadder oaepPadder) {
    return decrypt(input, padder: oaepPadder);
  }

  // TODO sign

  RSAPublicKey get toPublicKey => RSAPublicKey(n, e);

  String toString() => 'RSAPrivateKey(n: $n, e: $e, d: $d, p: $p, q: $q)';
}

bool _checkObjectId(ASN1Sequence sequence, String id) {
  if (sequence.elements.length != 2) {
    throw Exception("Invalid structure");
  }

  if (sequence.elements.first is! ASN1ObjectIdentifier) {
    throw Exception("Invalid structure");
  }

  return (sequence.elements.first as ASN1ObjectIdentifier).identifier == id;
}
