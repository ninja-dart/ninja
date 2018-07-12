import 'dart:convert';
import 'dart:typed_data';
import 'package:pointycastle/pointycastle.dart' as pointy;
import 'package:pointycastle/export.dart' as pointy;
import 'package:ninja/utils/hex_string.dart';
import 'package:ninja/ninja.dart';

class AESEncoder extends Converter<String, String> {
  final Uint8List key;

  final Padder padder;

  final _cipher = pointy.AESFastEngine();

  AESEncoder(String key, {this.padder: const PKCS7Padder()})
      : key = Uint8List.fromList(key.codeUnits);

  AESEncoder.fromBytes(this.key, {this.padder: const PKCS7Padder()});

  @override
  String convert(String input) {
    _cipher.reset();
    _cipher.init(true, pointy.KeyParameter(key));

    final inputBytes = Uint8List.fromList(input.codeUnits);
    Padded padded = padder.pad(_cipher.blockSize, inputBytes);

    var output = Uint8List(padded.totalBytes);

    int offset = 0;
    for (int i = 0; i < padded.totalBlocks; i++) {
      offset += _cipher.processBlock(padded[i], 0, output, offset);
    }

    return hexStringDecoder.convert(output);
  }
}

class AESDecoder extends Converter<String, String> {
  final Uint8List key;

  final Padder padder;

  final _cipher = pointy.AESFastEngine();

  AESDecoder(String key, {this.padder: const PKCS7Padder()})
      : key = Uint8List.fromList(key.codeUnits);

  AESDecoder.fromBytes(this.key, {this.padder: const PKCS7Padder()});

  @override
  String convert(String input) {
    _cipher.reset();
    _cipher.init(false, pointy.KeyParameter(key));

    final inputBytes = hexStringEncoder.convert(input);

    var output = Uint8List(inputBytes.lengthInBytes);

    for (int offset = 0; offset < inputBytes.lengthInBytes;) {
      offset += _cipher.processBlock(inputBytes, offset, output, offset);
    }

    return String.fromCharCodes(padder.unpad(_cipher.blockSize, output));
  }
}

class AES extends Codec<String, String> {
  @override
  final AESEncoder encoder;

  @override
  final AESDecoder decoder;

  factory AES(String key, {Padder padder: const PKCS7Padder()}) =>
      AES.fromBytes(Uint8List.fromList(key.codeUnits), padder: padder);

  factory AES.fromBytes(Uint8List key, {Padder padder: const PKCS7Padder()}) {
    var keyBytes = Uint8List.fromList(key);
    return AES.from(AESEncoder.fromBytes(keyBytes, padder: padder),
        AESDecoder.fromBytes(keyBytes, padder: padder));
  }

  AES.from(this.encoder, this.decoder);
}
