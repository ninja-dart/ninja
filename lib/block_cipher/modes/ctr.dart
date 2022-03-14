import 'dart:convert';
import 'dart:typed_data';

import 'package:ninja/ninja.dart';
import 'package:ninja/utils/listops.dart';

final ctrBlockCipherMode = CTRBlockCipherMode();

class CTRBlockCipherMode {
  CTRBlockCipherMode();

  Uint8List encrypt(BlockCipher cipher, /* String | Iterable<int> */ input,
      {Iterable<int>? iv, Padder padder = const PKCS7Padder()}) {

  }

  Iterable<int> decrypt(BlockCipher cipher, /* String | Uint8List */ input,
      {Iterable<int>? iv, Padder padder = const PKCS7Padder()}) {

  }
}