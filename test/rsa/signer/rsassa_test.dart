import 'package:ninja/asymmetric/rsa/encoder/emsaPkcs1V15.dart';
import 'package:ninja/asymmetric/rsa/rsa.dart';
import 'package:ninja/asymmetric/rsa/signer/rsassa_pks1_v15.dart';
import 'package:test/test.dart';

void main() {
  group('RSA.Signer.Rsassa', () {
    test('sign', () {
      final message = 'abcdefghijklmnopqrstuvwxyz\n';

      final privateKey = RSAPrivateKey.fromASN1(
          'MIIBOwIBAAJBAMv7Reawnxr0DfYN3IZbb5ih/XJGeLWDv7WuhTlie//c2TDXw/mW914VFyoBfxQxAezSj8YpuADiTwqDZl13wKMCAwEAAQJAYaTrFT8/KpvhgwOnqPlkNmB0/psVdW6X+tSMGag3S4cFid3nLkN384N6tZ+na1VWNkLy32Ndpxo6pQq4NSAbYQIhAPNlJsV+Snpg+JftgviV5+jOKY03bx29GsZF+umN6hD/AiEA1ouXAO2mVGRkBuoGXe3o/d5AOXj41vTB8D6IUGu8bF0CIQC6zah7LRmGYYSKPk0l8w+hmxFDBAexIGE7SZxwwm2iCwIhAInnDbe2CbyjDrx2/oKvopxTmDqY7HHWvzX6K8pthZ6tAiAww+DJoSx81QQpD8gY/BXjovadVtVROALaFFvdmN64sw==');
      // print(privateKey);

      final signer = RsassaPkcs1V15Signer(hasher: EmsaHasher.sha1);
      final signature = signer.sign(privateKey, message);
      // print(signature);
      expect(signature,
          'kTm+mPFs9T0i2mPLVZuwapMzjaajROKKQoXC2jP6y3CA0m56CUg3eaAW7rwgdgL8P5BJLC8vuBQ/D+MP2FVZPQ==');

      final publicKey = privateKey.toPublicKey;
      final verifier = RsassaPkcs1V15Verifier(hasher: EmsaHasher.sha1);
      // print(verifier.verify(signature, message) ? 'verified' : 'rejected');
      expect(verifier.verify(publicKey, signature, message), true);
    });
  });
}
