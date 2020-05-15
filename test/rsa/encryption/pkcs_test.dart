import 'package:ninja/ninja.dart';
import 'package:test/test.dart';

void main() {
  group('rsa.encryption.raw', () {
    final privateKey = RSAPrivateKey.fromASN1(
        'MIIBOwIBAAJBAMv7Reawnxr0DfYN3IZbb5ih/XJGeLWDv7WuhTlie//c2TDXw/mW914VFyoBfxQxAezSj8YpuADiTwqDZl13wKMCAwEAAQJAYaTrFT8/KpvhgwOnqPlkNmB0/psVdW6X+tSMGag3S4cFid3nLkN384N6tZ+na1VWNkLy32Ndpxo6pQq4NSAbYQIhAPNlJsV+Snpg+JftgviV5+jOKY03bx29GsZF+umN6hD/AiEA1ouXAO2mVGRkBuoGXe3o/d5AOXj41vTB8D6IUGu8bF0CIQC6zah7LRmGYYSKPk0l8w+hmxFDBAexIGE7SZxwwm2iCwIhAInnDbe2CbyjDrx2/oKvopxTmDqY7HHWvzX6K8pthZ6tAiAww+DJoSx81QQpD8gY/BXjovadVtVROALaFFvdmN64sw==');
    final publicKey = privateKey.toPublicKey;

    test('small_msg_endecrypt', () {
      final message = 'hello world!';
      String encrypted = publicKey.encryptPkcs(message);
      print(publicKey.encryptPkcs(message));
      String decrypted = privateKey.decryptPkcs(encrypted);

      expect(decrypted, message);
    });

    test('small_msg_dencryptOpenssl', () {
      final decoded = privateKey.decryptPkcs(hexDecode(
          '253D6BCFBE654D5B07179719ECB250218AFEBCF555FD6CC56C3C64838BE719B44484C7916106B81C722AF245886172A5233B44234B36E61186CA77E513404514'));
      expect(decoded, 'hello world!\n');
    });

    test('long_msg', () {
      final message =
          'Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...';
      String encrypted = publicKey.encryptPkcs(message);
      print(publicKey.encryptPkcs(message));
      String decrypted = privateKey.decryptPkcs(encrypted);

      expect(decrypted, message);
    });
  });
}
