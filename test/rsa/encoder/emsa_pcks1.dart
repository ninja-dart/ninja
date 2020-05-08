import 'dart:convert';

import 'package:ninja/asymmetric/rsa/encoder/emsaPkcs1V15.dart';
import 'package:test/test.dart';

void main() {
  group('EMSA-PKCS1-V1_5-ENCODE', () {
    test('', () {
      final out = emsaPkcs1V15Encode(
          utf8.encode("hello world!"), 256, EmsaHasher.sha256);
      print(out);
    });
  });
}
