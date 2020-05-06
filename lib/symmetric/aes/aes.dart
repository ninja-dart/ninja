import 'dart:typed_data';
import 'package:ninja/utils/hex_string.dart';
import 'package:ninja/ninja.dart';

import 'engine.dart';

class AESKey {
  final Uint8List keyBytes;

  final BlockPadder padder;

  AESKey(this.keyBytes, {this.padder = const PKCS7Padder()});

  factory AESKey.fromString(String key, {BlockPadder padder = const PKCS7Padder()}) => AESKey(Uint8List.fromList(key.codeUnits), padder: padder);

  String encrypt(String input) {
    final engine = AESFastEncryptionEngine(keyBytes);

    final inputBytes = Uint8List.fromList(input.codeUnits);
    final padded = padder.pad(engine.blockSize, inputBytes);

    final encryptedBytes = engine.process(padded);

    return hexEncoder.convert(encryptedBytes);
  }

  String decrypt(String input) {
    final engine = AESFastDecryptionEngine(keyBytes);

    final inputBytes = hexDecoder.convert(input);

    final output = engine.process(inputBytes);

    return String.fromCharCodes(padder.unpad(engine.blockSize, output));
  }
}
