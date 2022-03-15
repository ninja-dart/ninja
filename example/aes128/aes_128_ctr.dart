import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:ninja/ninja.dart';


void main() {
  // echo -n 'Dart' | openssl enc -aes-128-ctr -e -a -K 000102030405060708090a0b0c0d0e0f -iv 3ffabe88d6a25a9f4ce3141a1e388ab6 -p -nopad -nosalt
  // echo -n 'u0uz7g==' | base64 -d | openssl enc -aes-128-ctr -d -K 000102030405060708090a0b0c0d0e0f -iv 3ffabe88d6a25a9f4ce3141a1e388ab6 -nopad -nosalt
  final iv = CTRBlockCipherMode.makeRandomIV(random: Random(12345));
  final key = Uint8List.fromList(List.generate(16, (i) => i));
  print(key.toHex());
  print(iv.toHex());
  final aes = AESKey(key);
  String encoded = aes.encryptCtrToBase64('erqwerqwrqwerqwerqwerwqerqwerqwerqwerqwerqwerqwr', iv: iv);
  print(encoded);
  print(base64Decode(encoded).toHex());
  String decoded = aes.decryptCtrToUtf8(encoded, iv: iv);
  print(decoded);
}