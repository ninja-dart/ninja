import 'dart:convert';

import 'package:ninja/ninja.dart';
import 'package:ninja/padder/emePkcs1V1dot5.dart';
import 'package:test/test.dart';

void main() {
  group('EME-PKCS1-V1_5', () {
    final padder = EmePkcs1V1dot5Encoder();

    test('shortmsg', () {
      final message = utf8.encode('hello world!');
      // print('message: ${message.length} $message');
      final padded = padder.pad(32, message);
      // print(hexCodec.encode(padded));
      final unpadded = padder.unpad(32, padded).toList();
      // print('message: ${unpadded.length} $unpadded');
      expect(message, unpadded);
    });

    test('longmsg', () {
      final message = utf8.encode('Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...');
      // print('message: ${message.length} $message');
      final padded = padder.pad(32, message);
      // print(hexCodec.encode(padded));
      final unpadded = padder.unpad(32, padded).toList();
      // print('message: ${unpadded.length} $unpadded');
      expect(message, unpadded);
    });
  });
}