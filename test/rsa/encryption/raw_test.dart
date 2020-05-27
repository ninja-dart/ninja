import 'package:ninja/ninja.dart';
import 'package:test/test.dart';

void main() {
  group('rsa.encryption.raw', () {
    final privateKey = RSAPrivateKey.fromASN1(
        'MIIBOwIBAAJBAMv7Reawnxr0DfYN3IZbb5ih/XJGeLWDv7WuhTlie//c2TDXw/mW914VFyoBfxQxAezSj8YpuADiTwqDZl13wKMCAwEAAQJAYaTrFT8/KpvhgwOnqPlkNmB0/psVdW6X+tSMGag3S4cFid3nLkN384N6tZ+na1VWNkLy32Ndpxo6pQq4NSAbYQIhAPNlJsV+Snpg+JftgviV5+jOKY03bx29GsZF+umN6hD/AiEA1ouXAO2mVGRkBuoGXe3o/d5AOXj41vTB8D6IUGu8bF0CIQC6zah7LRmGYYSKPk0l8w+hmxFDBAexIGE7SZxwwm2iCwIhAInnDbe2CbyjDrx2/oKvopxTmDqY7HHWvzX6K8pthZ6tAiAww+DJoSx81QQpD8gY/BXjovadVtVROALaFFvdmN64sw==');
    final publicKey = privateKey.toPublicKey;

    test('small_msg', () {
      final message = 'hello world!';
      String encrypted = publicKey.encryptToBase64(message);
      expect(encrypted,
          'HqfFR+nuGx7Xf5kCkbTd1QSje7CYWeE3xDO8J+Ed8sW9ER/AN/s84OTZ8K+WSMNkh+P6CM3OiWgprRI+0a5jHg==');
      String decrypted = privateKey.decryptAsUtf8(encrypted, raw: true);
      expect(decrypted, message);
    });

    test('long_msg', () {
      final message =
          'Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...';
      String encrypted = publicKey.encryptToBase64(message);
      expect(encrypted,
          'UYr82kb5BJ3nm+i1JjE3ad6ni8Jz7CGAG0cENarXaum2a/CnfouejS4HaycXysouYi1U1vqydNFPd3D58rJXr53nRmyWmodn7n6D7EtFo+0T4sumbfyiU5HEhxBP0oi0+9o0w8dAFp1MFKCcfID2NlPD3zyt3fLPfyxXJZxaKlS2EuPuK/t5h2odMC6CVF3Fc/B2oIKOYQzXfAO85Qgwlmxoc5cwXfbQTctIf9P56tv4ZVdGWIQ+2tL/XTrjmKMHDBXImFzsiCdQZouS6tpHxqw5IMh82WcI5COKzDFBC5q5NC9ZgLbQXNnde4gZFls63uGpOLlC6Fgz4pK92YZ3vgu2cp+sL8PDw4rkjWF0X//T0UcSCiJa+rPfLYnEKj3TfVeyWVkpAVnAfYNs/3wov013e6SjhR6puYzTf7v5g3s=');
      String decrypted = privateKey.decryptAsUtf8(encrypted, raw: true);
      expect(decrypted, message);
    });
  });
}
