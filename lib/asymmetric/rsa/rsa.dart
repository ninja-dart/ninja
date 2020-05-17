import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart' as asn1lib;
import 'package:ninja/asymmetric/rsa/encoder/emsaPkcs1V15.dart';
import 'package:ninja/asymmetric/rsa/engine/decrypter.dart';
import 'package:ninja/asymmetric/rsa/engine/encrypter.dart';
import 'package:ninja/asymmetric/rsa/signer/rsassa_pks1_v15.dart';
import 'package:ninja/formats/asn1/asn1.dart';
import 'package:ninja/formats/pem/pem.dart';
import 'package:ninja/ninja.dart';
import 'package:ninja/utils/big_int.dart';
import 'package:ninja/utils/hex_string.dart';

/// Public key for RSA encryption
class RSAPublicKey {
  RSAPublicKey(this.n, this.e) {
    _engine = RSAEncryptionEngine(this);
  }

  factory RSAPublicKey.fromASN1(/* String | Iterable<int> */ input,
      {bool fromPkcs1 = false}) {
    if (!fromPkcs1) {
      final seq = ASN1Sequence.decode(input);
      if (seq.children.length != 2) {
        throw Exception('Invalid structure');
      }

      if (seq.children[1] is! ASN1BitString) {
        throw Exception('Invalid structure');
      }

      final bitString = seq.children[1] as ASN1BitString;

      if (bitString.unusedBits != 0) {
        throw Exception('Invalid structure');
      }

      if (seq.children[0] is! ASN1Sequence) {
        throw Exception('Invalid structure');
      } else {
        final algIdentifier = seq.children[0] as ASN1Sequence;

        if (algIdentifier.children.isEmpty) {
          throw Exception('Invalid structure');
        }

        if (algIdentifier.children.first is! ASN1ObjectIdentifier) {
          throw Exception('Invalid structure');
        }

        final ASN1ObjectIdentifier identifer = algIdentifier.children.first;

        if (identifer.objectIdentifierAsString != '1.2.840.113549.1.1.1') {
          throw Exception('Invalid structure');
        }

        input = bitString.bitString;
      }
    }

    final seq = ASN1Sequence.decode(input);

    if (seq.children.length != 2) {
      throw Exception('Invalid structure');
    }

    if (seq.children.any((e) => e is! ASN1Integer)) {
      throw Exception('Invalid structure');
    }

    final numbers =
        seq.children.cast<ASN1Integer>().map((e) => e.value).toList();

    return RSAPublicKey(numbers[0], numbers[1]);
  }

  // TODO better exceptions
  factory RSAPublicKey.fromASN1Old(String input) {
    final asn1 = asn1lib.ASN1Parser(base64Decode(input));
    if (!asn1.hasNext()) {
      throw Exception("Invalid structure");
    }
    final root = asn1.nextObject();
    if (root is! asn1lib.ASN1Sequence) throw Exception('Invalid structure');

    final rootChildren = (root as asn1lib.ASN1Sequence).elements;
    if (rootChildren.length != 2) throw Exception('Invalid structure');
    if (rootChildren.first is! asn1lib.ASN1Sequence) {
      throw Exception('Invalid structure');
    } else {
      final objSequence = rootChildren.first as asn1lib.ASN1Sequence;
      if (objSequence.elements.isEmpty) {
        throw Exception('Invalid structure');
      }

      if (objSequence.elements.first is! asn1lib.ASN1ObjectIdentifier) {
        throw Exception('Invalid input');
      } else {
        final identifier =
            (objSequence.elements.first as asn1lib.ASN1ObjectIdentifier)
                .identifier;
        if (identifier != '1.2.840.113549.1.1.1') {
          throw Exception('Invalid identifier');
        }
      }
    }

    if (rootChildren[1] is! asn1lib.ASN1BitString) {
      throw Exception('Invalid structure');
    }

    final inner = asn1lib.ASN1Sequence.fromBytes(
        (rootChildren[1] as asn1lib.ASN1BitString).contentBytes());
    if (inner.elements.length != 2) {
      throw Exception('Invalid structure');
    }

    if (inner.elements.any((e) => e is! asn1lib.ASN1Integer)) {
      throw Exception('Invalid structure');
    }

    final numbers = inner.elements
        .map<BigInt>(
            (e) => bytesToBigInt((e as asn1lib.ASN1Integer).valueBytes()))
        .toList();

    return RSAPublicKey(numbers[0], numbers[1]);
  }

  factory RSAPublicKey.fromPEM(String input) {
    final pem = PemPart.decodeLabelled(input, ['RSA PUBLIC KEY', 'PUBLIC KEY']);
    return RSAPublicKey.fromASN1(pem.data,
        fromPkcs1: pem.label == 'RSA PUBLIC KEY');
  }

  /// Modulus
  final BigInt n;

  /// Public exponent
  final BigInt e;

  RSAEncryptionEngine _engine;

  RSAEncryptionEngine get engine => _engine;

  int get blockSize => engine.blockSize;

  Iterable<int> encryptToBytes(/* String | Iterable<int> */ input,
      {Padder padder}) {
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

  String encrypt(/* String | Iterable<int> */ input, {Padder padder}) {
    return base64Encode(encryptToBytes(input, padder: padder));
  }

  String encryptToHex(/* String | Iterable<int> */ input, {Padder padder}) {
    return hexEncode(encryptToBytes(input, padder: padder));
  }

  Iterable<int> encryptPkcsToBytes(/* String | Iterable<int> */ input,
      {Random rand}) {
    return encryptToBytes(input, padder: EmePkcs1V15Encoder(rand: rand));
  }

  String encryptPkcs(/* String | Iterable<int> */ input, {Random rand}) {
    return encrypt(input, padder: EmePkcs1V15Encoder(rand: rand));
  }

  String encryptPkcsToHex(/* String | Iterable<int> */ input, {Random rand}) {
    return encryptToHex(input, padder: EmePkcs1V15Encoder(rand: rand));
  }

  Iterable<int> encryptOaepToBytes(/* String | Iterable<int> */ input,
      {OAEPPadder oaepPadder}) {
    return encryptToBytes(input, padder: oaepPadder ?? oaepPadder);
  }

  String encryptOaep(/* String | Iterable<int> */ input,
      {OAEPPadder oaepPadder}) {
    return encrypt(input, padder: oaepPadder ?? sha1OaepPadder);
  }

  String encryptOaepToHex(/* String | Iterable<int> */ input,
      {OAEPPadder oaepPadder}) {
    return encryptToHex(input, padder: oaepPadder ?? sha1OaepPadder);
  }

  bool verifySsaPkcs1V15(/* String | List<int> | BigInt */ signature,
      final /* String | List<int> | BigInt */ msg,
      {EmsaHasher hasher}) {
    return RsassaPkcs1V15Verifier(this, hasher: hasher).verify(signature, msg);
  }

  String toASN1({bool toPkcs1 = false}) {
    final encoded = ASN1Sequence([ASN1Integer(n), ASN1Integer(e)]).encode();
    if (toPkcs1) {
      return base64Encode(encoded);
    }
    return base64Encode(ASN1Sequence([
      ASN1Sequence([
        ASN1ObjectIdentifier.fromString(
            '1.2.840.113549.1.1.1'), /* TODO parameters */
        ASN1Null(),
      ]),
      ASN1BitString(encoded)
    ]).encode());
  }

  String toPem({bool toPkcs1 = false}) {
    String asn1 = toASN1(toPkcs1: toPkcs1);
    String label = toPkcs1 ? 'RSA PUBLIC KEY' : 'PUBLIC KEY';
    return PemPart(label, asn1).toString();
  }

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
    final p = asn1lib.ASN1Parser(base64.decode(input));
    if (!p.hasNext()) throw Exception('Invalid structure');
    final rootSequence = p.nextObject();
    if (rootSequence is! asn1lib.ASN1Sequence) {
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
    return RSAPrivateKey.fromASN1(
        PemPart.decodeLabelled(input, ['RSA PRIVATE KEY', 'PRIVATE KEY']).data);
  }

  static RSAPrivateKey _fromASN1Sequence(asn1lib.ASN1Sequence rootSequence) {
    final rootChildren = rootSequence.elements;
    if (rootChildren.length < 6) {
      throw Exception('Invalid structure');
    }

    final relevant = rootChildren.skip(1).take(5);
    if (relevant.any((e) => e is! asn1lib.ASN1Integer)) {
      throw Exception('Invalid structure');
    }

    final bigInts = relevant
        .map((e) => bytesToBigInt((e as asn1lib.ASN1Integer).valueBytes()))
        .toList();
    return RSAPrivateKey(
        bigInts[0], bigInts[1], bigInts[2], bigInts[3], bigInts[4]);
  }

  static asn1lib.ASN1Sequence _isPkcs8(asn1lib.ASN1Sequence rootSequence) {
    if (rootSequence.elements.length != 3) return null;

    if (rootSequence.elements[1] is! asn1lib.ASN1Sequence) return null;

    if (!_checkObjectId(rootSequence.elements[1], "1.2.840.113549.1.1.1")) {
      return null;
    }

    if (rootSequence.elements[2] is! asn1lib.ASN1OctetString) {
      throw Exception("Invalid structure");
    }

    final sequence = asn1lib.ASN1Sequence.fromBytes(
        (rootSequence.elements[2] as asn1lib.ASN1OctetString).valueBytes());

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
      {Padder padder, bool raw = false}) {
    Uint8List inputBytes;
    if (input is String) {
      inputBytes = base64Decode(input);
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
      {Padder padder, bool raw = false}) {
    return utf8
        .decode(decryptToBytes(input, padder: padder, raw: raw).toList());
  }

  Iterable<int> decryptPkcsToBytes(/* String | List<int> */ input) {
    return decryptToBytes(input, padder: EmePkcs1V15Encoder());
  }

  String decryptPkcs(/* String | List<int> */ input) {
    return decrypt(input, padder: EmePkcs1V15Encoder());
  }

  Iterable<int> decryptOaepToBytes(/* String | List<int> */ input,
      {OAEPPadder oaepPadder}) {
    return decryptToBytes(input, padder: oaepPadder ?? sha1OaepPadder);
  }

  String decryptOaep(/* String | List<int> */ input, {OAEPPadder oaepPadder}) {
    return decrypt(input, padder: oaepPadder ?? sha1OaepPadder);
  }

  List<int> signSsaPkcs1V15ToBytes(final /* String | List<int> | BigInt */ msg,
      {EmsaHasher hasher}) {
    return RsassaPkcs1V15Signer(this, hasher: hasher).signToBytes(msg);
  }

  String signSsaPkcs1V15(/* String | List<int> | BigInt */ msg,
      {EmsaHasher hasher}) {
    return RsassaPkcs1V15Signer(this, hasher: hasher).sign(msg);
  }

  RSAPublicKey get toPublicKey => RSAPublicKey(n, e);

  // TODO toASN1

  // TODO toPEM

  String toString() => 'RSAPrivateKey(n: $n, e: $e, d: $d, p: $p, q: $q)';
}

bool _checkObjectId(asn1lib.ASN1Sequence sequence, String id) {
  if (sequence.elements.length != 2) {
    throw Exception("Invalid structure");
  }

  if (sequence.elements.first is! asn1lib.ASN1ObjectIdentifier) {
    throw Exception("Invalid structure");
  }

  return (sequence.elements.first as asn1lib.ASN1ObjectIdentifier).identifier ==
      id;
}
