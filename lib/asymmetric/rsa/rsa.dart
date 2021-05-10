import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:ninja/asymmetric/rsa/signer/emsa_pss.dart';
import 'package:ninja/padder/mgf/mgf.dart';
import 'package:ninja_prime/ninja_prime.dart';

import 'package:ninja/asymmetric/rsa/encoder/emsaPkcs1v15.dart';
import 'package:ninja/asymmetric/rsa/engine/decrypter.dart';
import 'package:ninja/asymmetric/rsa/engine/encrypter.dart';
import 'package:ninja/asymmetric/rsa/signer/rsassa_pks1_v15.dart';
import 'package:ninja_asn1/ninja_asn1.dart';
import 'package:ninja_pem/ninja_pem.dart';
import 'package:ninja/ninja.dart';
import 'package:ninja_hex/ninja_hex.dart';

export 'signer/signer.dart';

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
      }

      final algIdentifier = seq.children[0] as ASN1Sequence;

      if (algIdentifier.children.isEmpty) {
        throw Exception('Invalid structure');
      }

      if (algIdentifier.children.first is! ASN1ObjectIdentifier) {
        throw Exception('Invalid structure');
      }

      final ASN1ObjectIdentifier identifer =
          algIdentifier.children.first as ASN1ObjectIdentifier;

      if (identifer.objectIdentifierAsString != '1.2.840.113549.1.1.1') {
        throw Exception('Invalid structure');
      }

      input = bitString.bitString;
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

  factory RSAPublicKey.fromPEM(String input) {
    final pem = PemPart.decodeLabelled(input, ['RSA PUBLIC KEY', 'PUBLIC KEY']);
    return RSAPublicKey.fromASN1(pem.data,
        fromPkcs1: pem.label == 'RSA PUBLIC KEY');
  }

  /// Modulus
  final BigInt n;

  /// Public exponent
  final BigInt e;

  RSAEncryptionEngine? _engine;

  RSAEncryptionEngine get engine => _engine!;

  int get blockSize => engine.blockSize;

  int get bitSize => n.bitLength;

  Iterable<int> encrypt(/* String | Iterable<int> */ input, {Padder? padder}) {
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

  String encryptToBase64(/* String | Iterable<int> */ input, {Padder? padder}) {
    final bytes = encrypt(input, padder: padder);
    return base64Encode(bytes.toList());
  }

  String encryptToHex(/* String | Iterable<int> */ input, {Padder? padder}) {
    return hexEncode(encrypt(input, padder: padder));
  }

  Iterable<int> encryptPkcs1v15(/* String | Iterable<int> */ input,
      {Random? rand}) {
    return encrypt(input, padder: EmePkcs1v15Encoder(rand: rand));
  }

  String encryptPkcs1v15ToBase64(/* String | Iterable<int> */ input,
      {Random? rand}) {
    return encryptToBase64(input, padder: EmePkcs1v15Encoder(rand: rand));
  }

  String encryptPkcs1v15ToHex(/* String | Iterable<int> */ input,
      {Random? rand}) {
    return encryptToHex(input, padder: EmePkcs1v15Encoder(rand: rand));
  }

  Iterable<int> encryptOaep(/* String | Iterable<int> */ input,
      {OAEPPadder? oaepPadder}) {
    return encrypt(input, padder: oaepPadder ?? sha1OaepPadder);
  }

  String encryptOaepToBase64(/* String | Iterable<int> */ input,
      {OAEPPadder? oaepPadder}) {
    return encryptToBase64(input, padder: oaepPadder ?? sha1OaepPadder);
  }

  String encryptOaepToHex(/* String | Iterable<int> */ input,
      {OAEPPadder? oaepPadder}) {
    return encryptToHex(input, padder: oaepPadder ?? sha1OaepPadder);
  }

  bool verifySsaPkcs1v15(/* String | List<int> | BigInt */ signature,
      final /* String | List<int> | BigInt */ msg,
      {EmsaHasher? hasher}) {
    return RsassaPkcs1v15Verifier(hasher: hasher).verify(this, signature, msg);
  }

  bool verifySsaPss(/* String | List<int> | BigInt */ signature,
      final /* String | List<int> | BigInt */ msg,
      {Mgf? mgf,
      Hash? hasher,
      int saltLength = 10,
      RsaSsaPssVerifier? verifier}) {
    verifier ??=
        RsaSsaPssVerifier(mgf: mgf, hasher: hasher, saltLength: saltLength);
    return verifier.verify(this, signature, msg);
  }

  String toASN1({bool toPkcs1 = false, Iterable<ASN1Object>? parameters}) {
    final encoded = ASN1Sequence([ASN1Integer(n), ASN1Integer(e)]).encode();
    if (toPkcs1) {
      return base64Encode(encoded);
    }
    return base64Encode(ASN1Sequence([
      ASN1Sequence([
        ASN1ObjectIdentifier.fromString('1.2.840.113549.1.1.1'),
        ...(parameters != null && parameters.isNotEmpty
            ? parameters
            : [ASN1Null()]),
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

  factory RSAPrivateKey.fromPrimaries(BigInt p, BigInt q,
      {BigInt? publicExponent}) {
    publicExponent ??= BigInt.from(0x01001);

    final n = p * q;

    BigInt d = publicExponent.modInverse((p - BigInt.one) * (q - BigInt.one));

    return RSAPrivateKey(n, publicExponent, d, p, q);
  }

  factory RSAPrivateKey.generate(int keySize, {BigInt? publicExponent}) {
    publicExponent ??= BigInt.from(0x01001);

    BigInt p;
    while (true) {
      p = randomPrimeBigInt(keySize ~/ 2);

      if (p % publicExponent == BigInt.one) {
        continue;
      }

      if (publicExponent.gcd(p - BigInt.one) == BigInt.one) {
        break;
      }
    }

    BigInt q;
    BigInt n;
    int qBitLength = keySize - p.bitLength;
    while (true) {
      q = randomPrimeBigInt(qBitLength);

      if (p == q) {
        continue;
      }

      if (q % publicExponent == BigInt.one) {
        continue;
      }

      if (publicExponent.gcd(q - BigInt.one) != BigInt.one) {
        continue;
      }

      n = p * q;
      final nBitlength = n.bitLength;
      if (nBitlength != keySize) {
        continue;
      }

      if (p < q) {
        BigInt tmp = p;
        p = q;
        q = tmp;
      }

      return RSAPrivateKey.fromPrimaries(p, q, publicExponent: publicExponent);
    }
  }

  factory RSAPrivateKey.fromASN1(dynamic /* String | Iterable<int> */ input,
      {bool fromPkcs1 = true}) {
    if (!fromPkcs1) {
      final seq = ASN1Sequence.decode(input);
      if (seq.children.length != 3) {
        throw Exception('Invalid structure');
      }

      if (seq.children[2] is! ASN1OctetString) {
        throw Exception('Invalid structure');
      }

      final bitString = seq.children[2] as ASN1OctetString;

      if (seq.children[1] is! ASN1Sequence) {
        throw Exception('Invalid structure');
      }

      final algIdentifier = seq.children[1] as ASN1Sequence;

      if (algIdentifier.children.isEmpty) {
        throw Exception('Invalid structure');
      }

      if (algIdentifier.children.first is! ASN1ObjectIdentifier) {
        throw Exception('Invalid structure');
      }

      final ASN1ObjectIdentifier identifer =
          algIdentifier.children.first as ASN1ObjectIdentifier;

      if (identifer.objectIdentifierAsString != '1.2.840.113549.1.1.1') {
        throw Exception('Invalid structure');
      }

      input = bitString.value;
    }

    final seq = ASN1Sequence.decode(input);

    if (seq.children.length < 9) {
      throw Exception('Invalid structure');
    }

    final relevant = seq.children.skip(1).take(5);
    if (relevant.any((el) => el is! ASN1Integer)) {
      throw Exception('Invalid structure');
    }

    final bigInts = relevant.map((e) => (e as ASN1Integer).value).toList();
    return RSAPrivateKey(
        bigInts[0], bigInts[1], bigInts[2], bigInts[3], bigInts[4]);
  }

  factory RSAPrivateKey.fromPEM(String input) {
    final pem =
        PemPart.decodeLabelled(input, ['RSA PRIVATE KEY', 'PRIVATE KEY']);
    return RSAPrivateKey.fromASN1(pem.data,
        fromPkcs1: pem.label == 'RSA PRIVATE KEY');
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

  RSADecryptionEngine? _engine;

  RSADecryptionEngine get engine => _engine!;

  int get blockSize => engine.blockSize;

  int get bitSize => n.bitLength;

  Iterable<int> decrypt(/* String | List<int> */ input,
      {Padder? padder, bool raw = false}) {
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
    Iterable<int> unpadded = engine.process(inputBytes, dontPadLastBlock: raw);
    if (padder == null) {
      return unpadded;
    }
    return padder.unpad(blockSize, unpadded);
  }

  String decryptToUtf8(/* String | List<int> */ input,
      {Padder? padder, bool raw = false}) {
    return utf8.decode(decrypt(input, padder: padder, raw: raw).toList());
  }

  Iterable<int> decryptPkcs1v15(/* String | List<int> */ input) {
    return decrypt(input, padder: EmePkcs1v15Encoder());
  }

  String decryptPkcs1v15ToUtf8(/* String | List<int> */ input) {
    return decryptToUtf8(input, padder: EmePkcs1v15Encoder());
  }

  Iterable<int> decryptOaep(/* String | List<int> */ input,
      {OAEPPadder? oaepPadder}) {
    return decrypt(input, padder: oaepPadder ?? sha1OaepPadder);
  }

  String decryptOaepToUtf8(/* String | List<int> */ input,
      {OAEPPadder? oaepPadder}) {
    return decryptToUtf8(input, padder: oaepPadder ?? sha1OaepPadder);
  }

  List<int> signSsaPkcs1v15(final /* String | List<int> | BigInt */ msg,
      {EmsaHasher? hasher}) {
    return RsassaPkcs1v15Signer(hasher: hasher).sign(this, msg);
  }

  String signSsaPkcs1v15ToBase64(/* String | List<int> | BigInt */ msg,
      {EmsaHasher? hasher}) {
    return RsassaPkcs1v15Signer(hasher: hasher).signToBase64(this, msg);
  }

  Iterable<int> signPss(final /* String | List<int> | BigInt */ msg,
      {Mgf? mgf,
      Hash? hasher,
      int saltLength = 10,
      Random? saltGenerator,
      RsaSsaPssSigner? signer}) {
    signer ??= RsaSsaPssSigner(
        mgf: mgf,
        hasher: hasher,
        saltLength: saltLength,
        saltGenerator: saltGenerator);
    return signer.sign(this, msg);
  }

  String signPssToBase64(final /* String | List<int> | BigInt */ msg,
      {Mgf? mgf,
      Hash? hasher,
      int saltLength = 10,
      Random? saltGenerator,
      RsaSsaPssSigner? signer}) {
    signer ??= RsaSsaPssSigner(
        mgf: mgf,
        hasher: hasher,
        saltLength: saltLength,
        saltGenerator: saltGenerator);
    return signer.signToBase64(this, msg);
  }

  RSAPublicKey get toPublicKey => RSAPublicKey(n, e);

  String toASN1({bool toPkcs1 = true, Iterable<ASN1Object>? parameters}) {
    final dModP = d % (p - BigInt.from(1));
    final dModQ = d % (q - BigInt.from(1));
    final coefficient = q.modInverse(p);
    final encoded = ASN1Sequence([
      ASN1Integer.fromNum(0),
      ASN1Integer(n),
      ASN1Integer(e),
      ASN1Integer(d),
      ASN1Integer(p),
      ASN1Integer(q),
      ASN1Integer(dModP),
      ASN1Integer(dModQ),
      ASN1Integer(coefficient),
    ]).encode();
    if (toPkcs1) {
      return base64Encode(encoded);
    }
    return base64Encode(ASN1Sequence([
      ASN1Integer.fromNum(0),
      ASN1Sequence([
        ASN1ObjectIdentifier.fromString('1.2.840.113549.1.1.1'),
        ...(parameters != null && parameters.isNotEmpty
            ? parameters
            : [ASN1Null()]),
      ]),
      ASN1OctetString(encoded)
    ]).encode());
  }

  String toPem({bool toPkcs1 = true}) {
    String asn1 = toASN1(toPkcs1: toPkcs1);
    String label = toPkcs1 ? 'RSA PRIVATE KEY' : 'PRIVATE KEY';
    return PemPart(label, asn1).toString();
  }

  String toString() => 'RSAPrivateKey(n: $n, e: $e, d: $d, p: $p, q: $q)';
}
