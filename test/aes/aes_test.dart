import 'package:ninja/ninja.dart';
import 'package:test/test.dart';

void main() {
  group('AES-128-ECB', () {
    final aesKey1 = AESKey.fromHex('B025700C28E7F0F97F7EA8EEEEC29F9F');

    group('short_padded', () {
      test('Encoding', () {
        String value = aesKey1.encryptToBase64('hello world!\n');
        expect(value, 'Sesg9NhOm+eKFe9hU/mfSA==');
      });

      test('Decode', () {
        final decoded = aesKey1.decryptToUtf8('Sesg9NhOm+eKFe9hU/mfSA==');
        expect(decoded, 'hello world!\n');
      });
    });

    group('short', () {
      test('Encoding', () {
        String value = aesKey1.encryptToBase64('hello world!!!!\n');
        expect(value, 'PGxrnKUS/zhDneaO3c0APkKdSMS47iRQ8KLISthNtNU=');
      });

      test('Decode', () {
        final decoded = aesKey1
            .decryptToUtf8('PGxrnKUS/zhDneaO3c0APkKdSMS47iRQ8KLISthNtNU=');
        expect(decoded, 'hello world!!!!\n');
      });
    });

    group('long', () {
      test('Encoding', () {
        String value = aesKey1.encryptToBase64(
            'Lorem ipsum dolor sit amet, consectetur adipiscing elit ........\n');
        expect(value,
            'MR2pq72G8HPSyM8CzTcWkq5771gkoBPU/4fSQQSKVJUGjnDw5jrmCDchRIsd2XrfiWsbYG63PjfIG+OOJuVuqHgivoT6O+DtU5/4femIJTo=');
      });

      test('Decode', () {
        final decoded = aesKey1.decryptToUtf8(
            'MR2pq72G8HPSyM8CzTcWkq5771gkoBPU/4fSQQSKVJUGjnDw5jrmCDchRIsd2XrfiWsbYG63PjfIG+OOJuVuqHgivoT6O+DtU5/4femIJTo=');
        expect(decoded,
            'Lorem ipsum dolor sit amet, consectetur adipiscing elit ........\n');
      });
    });
  });
}
