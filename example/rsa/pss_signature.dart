import 'package:ninja/asymmetric/rsa/rsa.dart';
import 'package:ninja/asymmetric/rsa/signer/emsa_pss.dart';

void main() {
  final message = 'abcdefghijklmnopqrstuvwxyz\n';

  final privateKey = RSAPrivateKey.fromASN1(
      'MIIBOwIBAAJBAMv7Reawnxr0DfYN3IZbb5ih/XJGeLWDv7WuhTlie//c2TDXw/mW914VFyoBfxQxAezSj8YpuADiTwqDZl13wKMCAwEAAQJAYaTrFT8/KpvhgwOnqPlkNmB0/psVdW6X+tSMGag3S4cFid3nLkN384N6tZ+na1VWNkLy32Ndpxo6pQq4NSAbYQIhAPNlJsV+Snpg+JftgviV5+jOKY03bx29GsZF+umN6hD/AiEA1ouXAO2mVGRkBuoGXe3o/d5AOXj41vTB8D6IUGu8bF0CIQC6zah7LRmGYYSKPk0l8w+hmxFDBAexIGE7SZxwwm2iCwIhAInnDbe2CbyjDrx2/oKvopxTmDqY7HHWvzX6K8pthZ6tAiAww+DJoSx81QQpD8gY/BXjovadVtVROALaFFvdmN64sw==');

  final signer = RsaSsaPssSigner(saltLength: 10);
  final signature = signer.signToBase64(privateKey, message);
  print(signature);

  final publicKey = privateKey.toPublicKey;
  final verifier = RsaSsaPssVerifier(saltLength: 10);
  print(verifier.verify(publicKey, signature, message));
  print(verifier.extractSalt(publicKey, signature));
}
