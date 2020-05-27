import 'dart:convert';

import 'package:ninja/ninja.dart';
import 'package:ninja_openssl/ninja_openssl.dart';
import 'package:test/test.dart';

void main() {
  group('rsa.oaep', () {
    final privateKey = RSAPrivateKey.fromASN1(
        'MIIBOwIBAAJBAMv7Reawnxr0DfYN3IZbb5ih/XJGeLWDv7WuhTlie//c2TDXw/mW914VFyoBfxQxAezSj8YpuADiTwqDZl13wKMCAwEAAQJAYaTrFT8/KpvhgwOnqPlkNmB0/psVdW6X+tSMGag3S4cFid3nLkN384N6tZ+na1VWNkLy32Ndpxo6pQq4NSAbYQIhAPNlJsV+Snpg+JftgviV5+jOKY03bx29GsZF+umN6hD/AiEA1ouXAO2mVGRkBuoGXe3o/d5AOXj41vTB8D6IUGu8bF0CIQC6zah7LRmGYYSKPk0l8w+hmxFDBAexIGE7SZxwwm2iCwIhAInnDbe2CbyjDrx2/oKvopxTmDqY7HHWvzX6K8pthZ6tAiAww+DJoSx81QQpD8gY/BXjovadVtVROALaFFvdmN64sw==');
    final publicKey = privateKey.toPublicKey;

    final smallMsg = 'hello world!\n';

    test('smallmsg.encrypt&decrypt', () {
      String encrypted = publicKey.encryptOaep(smallMsg);
      print(encrypted);
      String decrypted = privateKey.decryptOaep(encrypted);

      expect(decrypted, smallMsg);
    });

    test('smallmsg.encrypt.openssl', () async {
      String encrypted = publicKey.encryptOaep(smallMsg);
      print(encrypted);

      expect(
          utf8.decode(await decryptRsaOaep(privateKey.toPem(), encrypted,
              cleanupTempDirectory: false)),
          smallMsg);
    });

    test('smallmsg.decrypt.constant', () {
      String encrypted =
          'WwOeW77CHGzwB76RgmDbpJuyRWAVJnz/b1Vzd4UQbt/BTl8PKuuLWjQYxkeA3NtV8zfSzzJVmkLlQafCr2RK+Q==';
      final decoded = privateKey.decryptOaep(encrypted);
      expect(decoded, smallMsg);
    });

    test('smallmsg.decrypt.openssl', () async {
      final encrypted = await encryptRsaOaep(publicKey.toPem(), smallMsg,
          cleanupTempDirectory: false);
      print(base64Encode(encrypted));
      String decrypted = privateKey.decryptOaep(encrypted);
      expect(decrypted, smallMsg);
    });

    test('long_msg_endecrypt', () {
      final message =
          'Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...';
      String encrypted = publicKey.encryptOaep(message);
      print(encrypted);
      String decrypted = privateKey.decryptOaep(encrypted);

      expect(decrypted, message);
    });
  });
}
