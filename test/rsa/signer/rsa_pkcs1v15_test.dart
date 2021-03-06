import 'package:ninja/asymmetric/rsa/encoder/emsaPkcs1v15.dart';
import 'package:ninja/asymmetric/rsa/rsa.dart';
import 'package:ninja/asymmetric/rsa/signer/rsassa_pks1_v15.dart';
import 'package:ninja_openssl/ninja_openssl.dart';
import 'package:test/test.dart';

void main() {
  group('RSA.Signer.Rsassa', () {
    final message = 'abcdefghijklmnopqrstuvwxyz\n';

    final privateKey = RSAPrivateKey.fromASN1(
        'MIIBOwIBAAJBAMv7Reawnxr0DfYN3IZbb5ih/XJGeLWDv7WuhTlie//c2TDXw/mW914VFyoBfxQxAezSj8YpuADiTwqDZl13wKMCAwEAAQJAYaTrFT8/KpvhgwOnqPlkNmB0/psVdW6X+tSMGag3S4cFid3nLkN384N6tZ+na1VWNkLy32Ndpxo6pQq4NSAbYQIhAPNlJsV+Snpg+JftgviV5+jOKY03bx29GsZF+umN6hD/AiEA1ouXAO2mVGRkBuoGXe3o/d5AOXj41vTB8D6IUGu8bF0CIQC6zah7LRmGYYSKPk0l8w+hmxFDBAexIGE7SZxwwm2iCwIhAInnDbe2CbyjDrx2/oKvopxTmDqY7HHWvzX6K8pthZ6tAiAww+DJoSx81QQpD8gY/BXjovadVtVROALaFFvdmN64sw==');
    final publicKey = privateKey.toPublicKey;

    test('sign&verify', () {
      // print(privateKey);

      final signer = RsassaPkcs1v15Signer(hasher: EmsaHasher.sha1);
      final signature = signer.signToBase64(privateKey, message);
      // print(signature);
      expect(signature,
          'kTm+mPFs9T0i2mPLVZuwapMzjaajROKKQoXC2jP6y3CA0m56CUg3eaAW7rwgdgL8P5BJLC8vuBQ/D+MP2FVZPQ==');

      final verifier = RsassaPkcs1v15Verifier(hasher: EmsaHasher.sha1);
      expect(verifier.verify(publicKey, signature, message), true);
    });

    test('sign.openssl', () async {
      final signer = RsassaPkcs1v15Signer(hasher: EmsaHasher.sha256);
      final signature = signer.signToBase64(privateKey, message);

      expect(await verifyRsaPkcs1(publicKey.toPem(), signature, message), true);
    });

    test('verify.openssl', () async {
      final signature = await signRsaPkcs1(privateKey.toPem(), message);

      final verifier = RsassaPkcs1v15Verifier(hasher: EmsaHasher.sha256);
      expect(verifier.verify(publicKey, signature, message), true);
    });
  });
}
