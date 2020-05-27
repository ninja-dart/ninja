import 'package:ninja/ninja.dart';
import 'package:ninja_hex/ninja_hex.dart';
import 'package:test/test.dart';

void main() {
  group('AES-128-CBC', () {
    final aesKey1 = AESKey.fromHex('B025700C28E7F0F97F7EA8EEEEC29F9F');
    final iv = hexDecoder.convert('B025700C28E7F0F97F7EA8EEEEC29F9F');

    group('short_padded', () {
      test('Encoding', () {
        String value = aesKey1.encryptCbcToBase64('hello world!\n', iv: iv);
        expect(value, '3Mjz548+yTC9q+gRPF6+Nw==');
      });

      test('Decode', () {
        final decoded =
            aesKey1.decryptCbcToUtf8('3Mjz548+yTC9q+gRPF6+Nw==', iv: iv);
        expect(decoded, 'hello world!\n');
      });
    });

    group('short', () {
      test('Encoding', () {
        String value = aesKey1.encryptCbcToBase64('hello world!!!!\n', iv: iv);
        expect(value, 'S+uqDrS44gxjMWS/g+GLD1IrtN28rhuv063miOIaqr8=');
      });

      test('Decode', () {
        final decoded = aesKey1.decryptCbcToUtf8(
            'S+uqDrS44gxjMWS/g+GLD1IrtN28rhuv063miOIaqr8=',
            iv: iv);
        expect(decoded, 'hello world!!!!\n');
      });
    });

    group('long', () {
      test('Encoding', () {
        String value = aesKey1.encryptCbcToBase64(
            'Lorem ipsum dolor sit amet, consectetur adipiscing elit ........\n',
            iv: iv);
        expect(value,
            'RehLdYZ1dyyjZEIG8F/7R8wF0oELFxB6tMqVp6T6b/9RaOlireU5qbsFcyfcAVW08hHUC+b6UW61Co+BiWuxvWU0FnksTxs0RTQhEhdyLRI=');
      });

      test('Decode', () {
        final decoded = aesKey1.decryptCbcToUtf8(
            'RehLdYZ1dyyjZEIG8F/7R8wF0oELFxB6tMqVp6T6b/9RaOlireU5qbsFcyfcAVW08hHUC+b6UW61Co+BiWuxvWU0FnksTxs0RTQhEhdyLRI=',
            iv: iv);
        expect(decoded,
            'Lorem ipsum dolor sit amet, consectetur adipiscing elit ........\n');
      });
    });
  });
}
