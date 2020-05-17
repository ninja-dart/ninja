import 'package:ninja/ninja.dart';
import 'package:test/test.dart';

void main() {
  group('rsa.pem', () {
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

    test('publickey.pkcs1', () {
      final publicKey = RSAPublicKey.fromPEM(publicKeyPkcs1);
      final encoded = publicKey.toPem(toPkcs1: true);
      expect(encoded, publicKeyPkcs1);
    });

    test('publickey.pkcs8', () {
      final publicKey = RSAPublicKey.fromPEM(publicKeyPkcs8);
      final encoded = publicKey.toPem();
      expect(encoded, publicKeyPkcs8);
    });
  });
}
