import 'dart:convert';
import 'dart:typed_data';

import 'package:ninja/block_cipher/modes/cbc.dart';
import 'package:ninja/ninja.dart';
import 'package:ninja_hex/ninja_hex.dart';

import 'engine.dart';

export 'engine.dart';

class AESKey {
  final Uint8List keyBytes;

  final Padder padder;

  final AESFastEncryptionEngine _encryptionEngine;

  final AESFastDecryptionEngine _decryptionEngine;

  AESKey(this.keyBytes, {this.padder = const PKCS7Padder()})
      : _encryptionEngine = AESFastEncryptionEngine(keyBytes),
        _decryptionEngine = AESFastDecryptionEngine(keyBytes);

  factory AESKey.fromUTF8(String key, {Padder padder = const PKCS7Padder()}) =>
      AESKey(Uint8List.fromList(utf8.encode(key)), padder: padder);

  factory AESKey.fromBase64(String key,
          {Padder padder = const PKCS7Padder()}) =>
      AESKey(base64Decode(key), padder: padder);

  factory AESKey.fromHex(String key, {Padder padder = const PKCS7Padder()}) =>
      AESKey(hexDecoder.convert(key), padder: padder);

  Uint8List encrypt(/* String | Iterable<int> */ input) {
    if (input is String) {
      input = utf8.encode(input);
    }
    final padded = padder.pad(_encryptionEngine.blockSize, input);

    final encryptedBytes = _encryptionEngine.process(padded);

    return encryptedBytes;
  }

  String encryptToBase64(/* String | Iterable<int> */ input) {
    final encryptedBytes = encrypt(input);
    return base64Encode(encryptedBytes);
  }

  String encryptToHex(/* String | Iterable<int> */ input) {
    final encryptedBytes = encrypt(input);
    return hexEncoder.convert(encryptedBytes);
  }

  Iterable<int> decrypt(/* String | Uint8List */ input) {
    if (input is String) {
      input = base64Decode(input);
    }

    final decrypted = _decryptionEngine.process(input);
    final unpadded =
        padder.unpad(_decryptionEngine.blockSize, decrypted).toList();

    return unpadded;
  }

  String decryptToUtf8(/* String | Uint8List */ input) {
    final bytes = decrypt(input);
    return utf8.decode(bytes.toList());
  }

  Uint8List encryptCbc(/* String | Uint8List */ input,
      {Iterable<int>? iv, Padder padder = const PKCS7Padder()}) {
    return cbcBlockCipherMode.encrypt(_encryptionEngine, input,
        iv: iv, padder: padder);
  }

  String encryptCbcToBase64(/* String | Iterable<int> */ input,
      {Iterable<int>? iv, Padder padder = const PKCS7Padder()}) {
    final encryptedBytes = encryptCbc(input, iv: iv, padder: padder);
    return base64Encode(encryptedBytes);
  }

  String encryptCbcToHex(/* String | Iterable<int> */ input,
      {Iterable<int>? iv, Padder padder = const PKCS7Padder()}) {
    final encryptedBytes = encryptCbc(input, iv: iv, padder: padder);
    return hexEncoder.convert(encryptedBytes);
  }

  Iterable<int> decryptCbc(/* String | Uint8List */ input,
      {Iterable<int>? iv, Padder padder = const PKCS7Padder()}) {
    return cbcBlockCipherMode.decrypt(_decryptionEngine, input,
        iv: iv, padder: padder);
  }

  String decryptCbcToUtf8(/* String | Uint8List */ input,
      {Iterable<int>? iv, Padder padder = const PKCS7Padder()}) {
    final bytes = decryptCbc(input, iv: iv, padder: padder);
    return utf8.decode(bytes.toList());
  }

  Uint8List encryptCtr(/* String | Uint8List */ input,
      {required Uint8List iv, Padder? padder}) {
    return ctrBlockCipherMode.encrypt(_encryptionEngine, input,
        iv: iv, padder: padder);
  }

  String encryptCtrToBase64(/* String | Iterable<int> */ input,
      {required Uint8List iv, Padder? padder}) {
    final encryptedBytes = encryptCtr(input, iv: iv, padder: padder);
    return base64Encode(encryptedBytes);
  }

  String encryptCtrToHex(/* String | Iterable<int> */ input,
      {required Uint8List iv, Padder? padder}) {
    final encryptedBytes = encryptCtr(input, iv: iv, padder: padder);
    return hexEncoder.convert(encryptedBytes);
  }

  Iterable<int> decryptCtr(/* String | Uint8List */ input,
      {required Uint8List iv, Padder? padder}) {
    return ctrBlockCipherMode.decrypt(_encryptionEngine, input,
        iv: iv, padder: padder);
  }

  String decryptCtrToUtf8(/* String | Uint8List */ input,
      {required Uint8List iv, Padder? padder}) {
    final bytes = decryptCtr(input, iv: iv, padder: padder);
    return utf8.decode(bytes.toList());
  }
}
