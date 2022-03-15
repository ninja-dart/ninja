# ninja

Cryptography dart library to encrypt, decrypt, sign and verify messages

# RSA

## Encryption

### OAEP

```dart
void main() {
  final privateKeyPem = '''
-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAMv7Reawnxr0DfYN3IZbb5ih/XJGeLWDv7WuhTlie//c2TDXw/mW
914VFyoBfxQxAezSj8YpuADiTwqDZl13wKMCAwEAAQJAYaTrFT8/KpvhgwOnqPlk
NmB0/psVdW6X+tSMGag3S4cFid3nLkN384N6tZ+na1VWNkLy32Ndpxo6pQq4NSAb
YQIhAPNlJsV+Snpg+JftgviV5+jOKY03bx29GsZF+umN6hD/AiEA1ouXAO2mVGRk
BuoGXe3o/d5AOXj41vTB8D6IUGu8bF0CIQC6zah7LRmGYYSKPk0l8w+hmxFDBAex
IGE7SZxwwm2iCwIhAInnDbe2CbyjDrx2/oKvopxTmDqY7HHWvzX6K8pthZ6tAiAw
w+DJoSx81QQpD8gY/BXjovadVtVROALaFFvdmN64sw==
-----END RSA PRIVATE KEY-----''';

  final privateKey = RSAPrivateKey.fromPEM(privateKeyPem);
  final publicKey = privateKey.toPublicKey;

  String encrypted = publicKey.encryptOaepToBase64(
      'Lorem ipsum dolor sit amet, consectetur adipiscing elit...');
  print(encrypted);
  String decrypted = privateKey.decryptOaepToUtf8(encrypted);
  print(decrypted);
}
```

### pkcs1v15

```dart
main() {
  final privateKeyPem = '''
-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAMv7Reawnxr0DfYN3IZbb5ih/XJGeLWDv7WuhTlie//c2TDXw/mW
914VFyoBfxQxAezSj8YpuADiTwqDZl13wKMCAwEAAQJAYaTrFT8/KpvhgwOnqPlk
NmB0/psVdW6X+tSMGag3S4cFid3nLkN384N6tZ+na1VWNkLy32Ndpxo6pQq4NSAb
YQIhAPNlJsV+Snpg+JftgviV5+jOKY03bx29GsZF+umN6hD/AiEA1ouXAO2mVGRk
BuoGXe3o/d5AOXj41vTB8D6IUGu8bF0CIQC6zah7LRmGYYSKPk0l8w+hmxFDBAex
IGE7SZxwwm2iCwIhAInnDbe2CbyjDrx2/oKvopxTmDqY7HHWvzX6K8pthZ6tAiAw
w+DJoSx81QQpD8gY/BXjovadVtVROALaFFvdmN64sw==
-----END RSA PRIVATE KEY-----''';

  final privateKey = RSAPrivateKey.fromPEM(privateKeyPem);
  final publicKey = privateKey.toPublicKey;

  String encrypted = publicKey.encryptToBase64(
      'Lorem ipsum dolor sit amet, consectetur adipiscing elit...');
  print(encrypted);
  String decrypted = privateKey.decryptToUtf8(encrypted);
  print(decrypted);
}
```

## Signature

### RSASSA-PSS

```dart
void main() {
  final privateKeyPem = '''
-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAMv7Reawnxr0DfYN3IZbb5ih/XJGeLWDv7WuhTlie//c2TDXw/mW
914VFyoBfxQxAezSj8YpuADiTwqDZl13wKMCAwEAAQJAYaTrFT8/KpvhgwOnqPlk
NmB0/psVdW6X+tSMGag3S4cFid3nLkN384N6tZ+na1VWNkLy32Ndpxo6pQq4NSAb
YQIhAPNlJsV+Snpg+JftgviV5+jOKY03bx29GsZF+umN6hD/AiEA1ouXAO2mVGRk
BuoGXe3o/d5AOXj41vTB8D6IUGu8bF0CIQC6zah7LRmGYYSKPk0l8w+hmxFDBAex
IGE7SZxwwm2iCwIhAInnDbe2CbyjDrx2/oKvopxTmDqY7HHWvzX6K8pthZ6tAiAw
w+DJoSx81QQpD8gY/BXjovadVtVROALaFFvdmN64sw==
-----END RSA PRIVATE KEY-----''';

  final privateKey = RSAPrivateKey.fromPEM(privateKeyPem);
  final publicKey = privateKey.toPublicKey;

  final message = 'abcdefghijklmnopqrstuvwxyz\n';

  final signature = privateKey.signPssToBase64(message);
  print(signature);

  print(publicKey.verifySsaPss(signature, message));

  final verifier = RsaSsaPssVerifier(saltLength: 10);
  print(verifier.extractSalt(publicKey, signature));
}
```

### RSASSA-PKCS1-V1_5

```dart
void main() {
  final privateKeyPem = '''
-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAMv7Reawnxr0DfYN3IZbb5ih/XJGeLWDv7WuhTlie//c2TDXw/mW
914VFyoBfxQxAezSj8YpuADiTwqDZl13wKMCAwEAAQJAYaTrFT8/KpvhgwOnqPlk
NmB0/psVdW6X+tSMGag3S4cFid3nLkN384N6tZ+na1VWNkLy32Ndpxo6pQq4NSAb
YQIhAPNlJsV+Snpg+JftgviV5+jOKY03bx29GsZF+umN6hD/AiEA1ouXAO2mVGRk
BuoGXe3o/d5AOXj41vTB8D6IUGu8bF0CIQC6zah7LRmGYYSKPk0l8w+hmxFDBAex
IGE7SZxwwm2iCwIhAInnDbe2CbyjDrx2/oKvopxTmDqY7HHWvzX6K8pthZ6tAiAw
w+DJoSx81QQpD8gY/BXjovadVtVROALaFFvdmN64sw==
-----END RSA PRIVATE KEY-----''';

  final privateKey = RSAPrivateKey.fromPEM(privateKeyPem);
  final publicKey = privateKey.toPublicKey;

  final message = 'abcdefghijklmnopqrstuvwxyz\n';

  final signature = privateKey.signSsaPkcs1v15ToBase64(message);
  print(signature);

  print(publicKey.verifySsaPkcs1v15(signature, message));
}
```

## Keys

### Generate key

```dart
void main() {
  final privateKey = RSAPrivateKey.generate(1024);
  print(privateKey.p);
  print(privateKey.q);
  print(privateKey.n.bitLength);
}
```

## Load key from PEM

```dart
final publicKeyPkcs1 = '''
-----BEGIN RSA PUBLIC KEY-----
MEgCQQDL+0XmsJ8a9A32DdyGW2+Yof1yRni1g7+1roU5Ynv/3Nkw18P5lvdeFRcq
AX8UMQHs0o/GKbgA4k8Kg2Zdd8CjAgMBAAE=
-----END RSA PUBLIC KEY-----''';

final publicKeyPkcs8 = '''
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMv7Reawnxr0DfYN3IZbb5ih/XJGeLWD
v7WuhTlie//c2TDXw/mW914VFyoBfxQxAezSj8YpuADiTwqDZl13wKMCAwEAAQ==
-----END PUBLIC KEY-----''';

final privateKeyPkcs1 = '''
-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAMv7Reawnxr0DfYN3IZbb5ih/XJGeLWDv7WuhTlie//c2TDXw/mW
914VFyoBfxQxAezSj8YpuADiTwqDZl13wKMCAwEAAQJAYaTrFT8/KpvhgwOnqPlk
NmB0/psVdW6X+tSMGag3S4cFid3nLkN384N6tZ+na1VWNkLy32Ndpxo6pQq4NSAb
YQIhAPNlJsV+Snpg+JftgviV5+jOKY03bx29GsZF+umN6hD/AiEA1ouXAO2mVGRk
BuoGXe3o/d5AOXj41vTB8D6IUGu8bF0CIQC6zah7LRmGYYSKPk0l8w+hmxFDBAex
IGE7SZxwwm2iCwIhAInnDbe2CbyjDrx2/oKvopxTmDqY7HHWvzX6K8pthZ6tAiAw
w+DJoSx81QQpD8gY/BXjovadVtVROALaFFvdmN64sw==
-----END RSA PRIVATE KEY-----''';

final privateKeyPkcs8 = '''
-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAy/tF5rCfGvQN9g3c
hltvmKH9ckZ4tYO/ta6FOWJ7/9zZMNfD+Zb3XhUXKgF/FDEB7NKPxim4AOJPCoNm
XXfAowIDAQABAkBhpOsVPz8qm+GDA6eo+WQ2YHT+mxV1bpf61IwZqDdLhwWJ3ecu
Q3fzg3q1n6drVVY2QvLfY12nGjqlCrg1IBthAiEA82UmxX5KemD4l+2C+JXn6M4p
jTdvHb0axkX66Y3qEP8CIQDWi5cA7aZUZGQG6gZd7ej93kA5ePjW9MHwPohQa7xs
XQIhALrNqHstGYZhhIo+TSXzD6GbEUMEB7EgYTtJnHDCbaILAiEAiecNt7YJvKMO
vHb+gq+inFOYOpjscda/Nforym2Fnq0CIDDD4MmhLHzVBCkPyBj8FeOi9p1W1VE4
AtoUW92Y3riz
-----END PRIVATE KEY-----''';

void pkcs1() {
  final publicKey = RSAPublicKey.fromPEM(publicKeyPkcs1);
  print(publicKey.toPem(toPkcs1: true));
  final privateKey = RSAPrivateKey.fromPEM(privateKeyPkcs1);
  print(privateKey.toPem());
  print(privateKey.toPem(toPkcs1: false));
}

void pkcs8() {
  final publicKey = RSAPublicKey.fromPEM(publicKeyPkcs8);
  print(publicKey.toPem());
  final privateKey = RSAPrivateKey.fromPEM(privateKeyPkcs8);
  print(privateKey.toPem(toPkcs1: false));
}
```

# AES

## Encryption

```dart
main() {
  final aes = AESKey(Uint8List.fromList(List.generate(16, (i) => i)));
  String encoded = aes.encryptToBase64('Dart');
  print(encoded);
  String decoded = aes.decryptToUtf8(encoded);
  print(decoded);
}
```

# TODO

+ [ ] AES key derivation
+ [ ] More block cipher modes
    + [ ] CFB
    + [ ] OFB
    + [ ] GCM
    + [ ] ECB
    + [ ] PCBC
+ [ ] Curve based cryptography