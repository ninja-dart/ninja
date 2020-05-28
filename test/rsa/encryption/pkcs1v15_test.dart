import 'dart:convert';

import 'package:ninja/ninja.dart';
import 'package:ninja_hex/ninja_hex.dart';
import 'package:ninja_openssl/ninja_openssl.dart';
import 'package:test/test.dart';

void main() {
  group('rsa.encryption.raw', () {
    final privateKey = RSAPrivateKey.fromASN1(
        'MIIBOwIBAAJBAMv7Reawnxr0DfYN3IZbb5ih/XJGeLWDv7WuhTlie//c2TDXw/mW914VFyoBfxQxAezSj8YpuADiTwqDZl13wKMCAwEAAQJAYaTrFT8/KpvhgwOnqPlkNmB0/psVdW6X+tSMGag3S4cFid3nLkN384N6tZ+na1VWNkLy32Ndpxo6pQq4NSAbYQIhAPNlJsV+Snpg+JftgviV5+jOKY03bx29GsZF+umN6hD/AiEA1ouXAO2mVGRkBuoGXe3o/d5AOXj41vTB8D6IUGu8bF0CIQC6zah7LRmGYYSKPk0l8w+hmxFDBAexIGE7SZxwwm2iCwIhAInnDbe2CbyjDrx2/oKvopxTmDqY7HHWvzX6K8pthZ6tAiAww+DJoSx81QQpD8gY/BXjovadVtVROALaFFvdmN64sw==');
    final publicKey = privateKey.toPublicKey;

    final smallMsg = 'hello world!\n';
    final longMsg =
        'Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...\n';

    test('smallMsg.encrypt&decrypt', () {
      String encrypted = publicKey.encryptPkcs1v15ToBase64(smallMsg);
      print(publicKey.encryptPkcs1v15ToBase64(smallMsg));
      String decrypted = privateKey.decryptPkcs1v15ToUtf8(encrypted);

      expect(decrypted, smallMsg);
    });

    test('smallMsg.dencrypt.constant', () {
      final encrypted = hexDecode(
          '253D6BCFBE654D5B07179719ECB250218AFEBCF555FD6CC56C3C64838BE719B44484C7916106B81C722AF245886172A5233B44234B36E61186CA77E513404514');
      final decoded = privateKey.decryptPkcs1v15ToUtf8(encrypted);
      expect(decoded, smallMsg);
    });

    test('smallMsg.dencrypt.openssl', () async {
      final encrypted = await encryptRsaPkcs1v15(publicKey.toPem(), smallMsg);
      final decoded = privateKey.decryptPkcs1v15ToUtf8(encrypted);
      expect(decoded, smallMsg);
    });

    test('smallMsg.encrypt.openssl', () async {
      final encrypted = publicKey.encryptPkcs1v15ToBase64(smallMsg);

      expect(
          utf8.decode(await decryptRsaPkcs1v15(privateKey.toPem(), encrypted)),
          smallMsg);
    });

    test('longMsg.encrypt&decrypt', () {
      String encrypted = publicKey.encryptPkcs1v15ToBase64(longMsg);
      print(publicKey.encryptPkcs1v15ToBase64(longMsg));
      String decrypted = privateKey.decryptPkcs1v15ToUtf8(encrypted);

      expect(decrypted, longMsg);
    });
  });
}
