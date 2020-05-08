import 'dart:convert';

import 'package:ninja/padder/mgf/mgf.dart';
import 'package:test/test.dart';

void main() {
  group('MGF1', () {
    test('encode', () {
      print(mgf1Sha1.encode(10, utf8.encode('hello world!')));
      print(mgf1Sha1.encode(20, utf8.encode('hello world!')));
      print(mgf1Sha1.encode(100, utf8.encode('hello world!')));
      print(mgf1Sha1.encode(64, utf8.encode('hello world!')));
    });
  });
}