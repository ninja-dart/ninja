import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:ninja/ninja.dart';


void main() {
  // echo -n 'Dart' | openssl enc -aes-128-ctr -K 000102030405060708090a0b0c0d0e0f -iv 3ffabe88d6a25a9f4ce3141a1e388ab6
  final iv = CTRBlockCipherMode.makeRandomIV(random: Random(12345));
  final key = Uint8List.fromList(List.generate(16, (i) => i));
  print(key.toHex());
  print(iv.toHex());
  final aes = AESKey(key);
  String encoded = aes.encryptCbcToBase64('Dart', iv: iv);
  print(encoded);
  print(base64Decode(encoded).toHex());
  String decoded = aes.decryptCbcToUtf8(encoded, iv: iv);
  print(decoded);
}