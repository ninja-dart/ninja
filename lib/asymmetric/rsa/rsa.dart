import 'dart:convert';
import 'dart:typed_data';
import 'package:asn1lib/asn1lib.dart';
import 'package:ninja/utils/hex_string.dart';
import 'package:ninja/utils/big_int.dart';

part 'engine.dart';

/// Public key for RSA encryption
class RSAPublicKey {
  RSAPublicKey(this.n, this.e);

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

    final inner =
    ASN1Sequence.fromBytes((rootChildren[1] as ASN1BitString).contentBytes());
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

  Uint8List encryptToBytes(/* String | List<int> */ input) {
    final engine = RSAEncryptionEngine(this);
    Uint8List inputBytes;
    if(input is String) {
      inputBytes = Uint8List.fromList(input.codeUnits);
    } else if(input is Uint8List) {
      inputBytes = input;
    } else if(input is List<int>) {
      inputBytes = Uint8List.fromList(input);
    } else {
      throw ArgumentError('Should be String or List<int>');
    }
    return engine.process(inputBytes);
  }

  String encrypt(/* String | List<int> */ input) {
    return hexStringDecoder.convert(encryptToBytes(input));
  }

  // TODO verify

  String toString() => 'RSAPublicKey(n: $n, e: $e)';
}

/// Private key for RSA encryption
class RSAPrivateKey {
  RSAPrivateKey(this.n, this.e, this.d, this.p, this.q);

  factory RSAPrivateKey.generate() {
    // TODO
  }

  factory RSAPrivateKey.fromASN1(String input) {
    // TODO
  }

  factory RSAPrivateKey.fromPEM(String input) {
    // TODO
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

  Uint8List decryptToBytes(/* String | List<int> */ input) {
    final engine = RSADecryptionEngine(this);
    Uint8List inputBytes;
    if(input is String) {
      inputBytes = hexStringEncoder.convert(input);
    } else if(input is Uint8List) {
      inputBytes = input;
    } else if(input is List<int>) {
      inputBytes = Uint8List.fromList(input);
    } else {
      throw ArgumentError('Should be String or List<int>');
    }
    return engine.process(inputBytes);
  }

  String decrypt(/* String | List<int> */ input) {
    return String.fromCharCodes(decryptToBytes(input));
  }
}
