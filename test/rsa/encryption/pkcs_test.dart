import 'package:ninja/ninja.dart';
import 'package:test/test.dart';

void main() {
  group('rsa.encryption.raw', () {
    final privateKey = RSAPrivateKey.fromASN1(
        'MIIBOwIBAAJBAMv7Reawnxr0DfYN3IZbb5ih/XJGeLWDv7WuhTlie//c2TDXw/mW914VFyoBfxQxAezSj8YpuADiTwqDZl13wKMCAwEAAQJAYaTrFT8/KpvhgwOnqPlkNmB0/psVdW6X+tSMGag3S4cFid3nLkN384N6tZ+na1VWNkLy32Ndpxo6pQq4NSAbYQIhAPNlJsV+Snpg+JftgviV5+jOKY03bx29GsZF+umN6hD/AiEA1ouXAO2mVGRkBuoGXe3o/d5AOXj41vTB8D6IUGu8bF0CIQC6zah7LRmGYYSKPk0l8w+hmxFDBAexIGE7SZxwwm2iCwIhAInnDbe2CbyjDrx2/oKvopxTmDqY7HHWvzX6K8pthZ6tAiAww+DJoSx81QQpD8gY/BXjovadVtVROALaFFvdmN64sw==');
    final publicKey = privateKey.toPublicKey;

    test('small_msg', () {
      final message = 'hello world!';
      String encrypted = publicKey.encryptPkcs(message);
      print(publicKey.encryptPkcsToBase64(message));
      // expect(encrypted, '1ea7c547e9ee1b1ed77f990291b4ddd504a37bb09859e137c433bc27e11df2c5bd111fc037fb3ce0e4d9f0af9648c36487e3fa08cdce896829ad123ed1ae631e');
      String decrypted = privateKey.decryptPkcs(encrypted);

      expect(decrypted, message);
    });
    
    test('small_msg_encrypt', () {
      final decoded = privateKey.decryptPkcs('253D6BCFBE654D5B07179719ECB250218AFEBCF555FD6CC56C3C64838BE719B44484C7916106B81C722AF245886172A5233B44234B36E61186CA77E513404514');
      expect(decoded, 'hello world!');
    });
    
    test('long_msg', () {
      final message =
          'Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...';
      String encrypted = publicKey.encryptPkcs(message);
      print(publicKey.encryptPkcsToBase64(message));
      // expect(encrypted, '518afcda46f9049de79be8b526313769dea78bc273ec21801b470435aad76ae9b66bf0a77e8b9e8d2e076b2717caca2e622d54d6fab274d14f7770f9f2b257af9de7466c969a8767ee7e83ec4b45a3ed13e2cba66dfca25391c487104fd288b4fbda34c3c740169d4c14a09c7c80f63653c3df3cadddf2cf7f2c57259c5a2a54b612e3ee2bfb79876a1d302e82545dc573f076a0828e610cd77c03bce50830966c687397305df6d04dcb487fd3f9eadbf865574658843edad2ff5d3ae398a3070c15c8985cec882750668b92eada47c6ac3920c87cd96708e4238acc31410b9ab9342f5980b6d05cd9dd7b8819165b3adee1a938b942e85833e292bdd98677be0bb6729fac2fc3c3c38ae48d61745fffd3d147120a225afab3df2d89c42a3dd37d57b25959290159c07d836cff7c28bf4d777ba4a3851ea9b98cd37fbbf9837b');
      String decrypted = privateKey.decryptPkcs(encrypted);

      expect(decrypted, message);
    });
  });
}
