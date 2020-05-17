
import 'package:ninja/ninja.dart';

final publicKeyPkcs1 = '''
-----BEGIN RSA PUBLIC KEY-----
MEgCQQDL+0XmsJ8a9A32DdyGW2+Yof1yRni1g7+1roU5Ynv/3Nkw18P5lvdeFRcq
AX8UMQHs0o/GKbgA4k8Kg2Zdd8CjAgMBAAE=
-----END RSA PUBLIC KEY-----''';

final publicKeyPkcs8 = '''
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMv7Reawnxr0DfYN3IZbb5ih/XJGeLWD
v7WuhTlie//c2TDXw/mW914VFyoBfxQxAezSj8YpuADiTwqDZl13wKMCAwEAAQ==
-----END PUBLIC KEY-----
''';

final privateKeyPkcs8 = '''
-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAMv7Reawnxr0DfYN3IZbb5ih/XJGeLWDv7WuhTlie//c2TDXw/mW
914VFyoBfxQxAezSj8YpuADiTwqDZl13wKMCAwEAAQJAYaTrFT8/KpvhgwOnqPlk
NmB0/psVdW6X+tSMGag3S4cFid3nLkN384N6tZ+na1VWNkLy32Ndpxo6pQq4NSAb
YQIhAPNlJsV+Snpg+JftgviV5+jOKY03bx29GsZF+umN6hD/AiEA1ouXAO2mVGRk
BuoGXe3o/d5AOXj41vTB8D6IUGu8bF0CIQC6zah7LRmGYYSKPk0l8w+hmxFDBAex
IGE7SZxwwm2iCwIhAInnDbe2CbyjDrx2/oKvopxTmDqY7HHWvzX6K8pthZ6tAiAw
w+DJoSx81QQpD8gY/BXjovadVtVROALaFFvdmN64sw==
-----END RSA PRIVATE KEY-----
''';

void pkcs1() {
  final publicKey = RSAPublicKey.fromPEM(publicKeyPkcs1);
  print(publicKey.toPem(toPkcs1: true));
}

void pkcs8() {
  final publicKey = RSAPublicKey.fromPEM(publicKeyPkcs8);
  print(publicKey.toPem());
}

void main() {
  pkcs1();
  pkcs8();
}