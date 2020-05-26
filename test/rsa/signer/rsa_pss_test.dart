import 'dart:convert';

import 'package:ninja/asymmetric/rsa/rsa.dart';
import 'package:ninja_openssl/ninja_openssl.dart';
import 'package:test/test.dart';

void main() {
  group('RSA.signature.pss', () {
    final privateKey = RSAPrivateKey.fromASN1(
        'MIIBOwIBAAJBAMv7Reawnxr0DfYN3IZbb5ih/XJGeLWDv7WuhTlie//c2TDXw/mW914VFyoBfxQxAezSj8YpuADiTwqDZl13wKMCAwEAAQJAYaTrFT8/KpvhgwOnqPlkNmB0/psVdW6X+tSMGag3S4cFid3nLkN384N6tZ+na1VWNkLy32Ndpxo6pQq4NSAbYQIhAPNlJsV+Snpg+JftgviV5+jOKY03bx29GsZF+umN6hD/AiEA1ouXAO2mVGRkBuoGXe3o/d5AOXj41vTB8D6IUGu8bF0CIQC6zah7LRmGYYSKPk0l8w+hmxFDBAexIGE7SZxwwm2iCwIhAInnDbe2CbyjDrx2/oKvopxTmDqY7HHWvzX6K8pthZ6tAiAww+DJoSx81QQpD8gY/BXjovadVtVROALaFFvdmN64sw==');
    final publicKey = privateKey.toPublicKey;

    final messageAbcd = 'abcdefghijklmnopqrstuvwxyz\n';

    test('sign&verify', () {
      final signer = RsaSsaPssSigner(saltLength: 10);
      final signature = signer.sign(privateKey, messageAbcd);

      final verifier = RsaSsaPssVerifier(saltLength: 10);
      expect(verifier.verify(publicKey, signature, messageAbcd), true);
    });

    test('sign.withSalt', () {
      final signer = RsaSsaPssSigner(saltLength: 10);
      final signature = signer.sign(privateKey, messageAbcd,
          salt: base64Decode('Br7j7BXOigzA4A=='));
      expect(signature,
          'ryq2OCyestd7yDKCjZ8wTL6xXf5DKuyuT2HWdz28uIpt2wz8sjPcAj0TuzOskE6HC938iMbn9jFS30Lwr9BN9A==');
    });

    test('sign.openssl', () async {
      final signer = RsaSsaPssSigner(saltLength: 10);
      final signature = signer.sign(privateKey, messageAbcd);

      expect(
          await verifyRsaPss(publicKey.toPem(), signature, messageAbcd,
              saltLength: 10),
          true);
    });

    test('verify.constant', () {
      final signature =
          'ryq2OCyestd7yDKCjZ8wTL6xXf5DKuyuT2HWdz28uIpt2wz8sjPcAj0TuzOskE6HC938iMbn9jFS30Lwr9BN9A==';
      final verifier = RsaSsaPssVerifier(saltLength: 10);
      expect(verifier.verify(publicKey, signature, messageAbcd), true);
      expect(verifier.extractSalt(publicKey, signature), 'Br7j7BXOigzA4A==');
    });

    test('verify.openssl', () async {
      final signature =
          await signRsaPss(privateKey.toPem(), messageAbcd, saltLength: 10);
      final verifier = RsaSsaPssVerifier(saltLength: 10);
      expect(verifier.verify(publicKey, signature, messageAbcd), true);
    });
  });
}
