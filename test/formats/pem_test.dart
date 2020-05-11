import 'dart:convert';

import 'package:ninja/formats/pem/pem.dart';
import 'package:test/test.dart';

void main() {
  group('PEM', () {
    test('encode', () {
      expect(
          PemPart('KEY', base64Encode('hello world!\n'.codeUnits)).toString(),
          '''-----BEGIN KEY-----
aGVsbG8gd29ybGQhCg==
-----END KEY-----''');

      expect(
          PemPart(
                  'KEY1',
                  base64Encode(
                      'Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...\n'
                          .codeUnits))
              .toString(),
          '''-----BEGIN KEY1-----
TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2Np
bmcgZWxpdC4uLkxvcmVtIGlwc3VtIGRvbG9yIHNpdCBhbWV0LCBjb25zZWN0ZXR1
ciBhZGlwaXNjaW5nIGVsaXQuLi5Mb3JlbSBpcHN1bSBkb2xvciBzaXQgYW1ldCwg
Y29uc2VjdGV0dXIgYWRpcGlzY2luZyBlbGl0Li4uTG9yZW0gaXBzdW0gZG9sb3Ig
c2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4uLkxvcmVtIGlw
c3VtIGRvbG9yIHNpdCBhbWV0LCBjb25zZWN0ZXR1ciBhZGlwaXNjaW5nIGVsaXQu
Li4K
-----END KEY1-----''');
    });

    test('decode', () {
      expect(PemPart.decodeAll('''-----BEGIN KEY-----
aGVsbG8gd29ybGQhCg==
-----END KEY-----'''),
          [PemPart('KEY', base64Encode('hello world!\n'.codeUnits))]);
      expect(PemPart.decodeAll('''-----BEGIN KEY1-----
TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2Np
bmcgZWxpdC4uLkxvcmVtIGlwc3VtIGRvbG9yIHNpdCBhbWV0LCBjb25zZWN0ZXR1
ciBhZGlwaXNjaW5nIGVsaXQuLi5Mb3JlbSBpcHN1bSBkb2xvciBzaXQgYW1ldCwg
Y29uc2VjdGV0dXIgYWRpcGlzY2luZyBlbGl0Li4uTG9yZW0gaXBzdW0gZG9sb3Ig
c2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4uLkxvcmVtIGlw
c3VtIGRvbG9yIHNpdCBhbWV0LCBjb25zZWN0ZXR1ciBhZGlwaXNjaW5nIGVsaXQu
Li4K
-----END KEY1-----'''), [
        PemPart(
            'KEY1',
            base64Encode(
                'Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...\n'
                    .codeUnits))
      ]);
      expect(PemPart.decodeAll('''-----BEGIN KEY-----
aGVsbG8gd29ybGQhCg==
-----END KEY-----
-----BEGIN KEY1-----
TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2Np
bmcgZWxpdC4uLkxvcmVtIGlwc3VtIGRvbG9yIHNpdCBhbWV0LCBjb25zZWN0ZXR1
ciBhZGlwaXNjaW5nIGVsaXQuLi5Mb3JlbSBpcHN1bSBkb2xvciBzaXQgYW1ldCwg
Y29uc2VjdGV0dXIgYWRpcGlzY2luZyBlbGl0Li4uTG9yZW0gaXBzdW0gZG9sb3Ig
c2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4uLkxvcmVtIGlw
c3VtIGRvbG9yIHNpdCBhbWV0LCBjb25zZWN0ZXR1ciBhZGlwaXNjaW5nIGVsaXQu
Li4K
-----END KEY1-----'''), [
        PemPart('KEY', base64Encode('hello world!\n'.codeUnits)),
        PemPart(
            'KEY1',
            base64Encode(
                'Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...\n'
                    .codeUnits))
      ]);
    });

    test('decodeFirst', () {
      expect(PemPart.decodeFirst('''-----BEGIN KEY-----
aGVsbG8gd29ybGQhCg==
-----END KEY-----
-----BEGIN KEY1-----
TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2Np
bmcgZWxpdC4uLkxvcmVtIGlwc3VtIGRvbG9yIHNpdCBhbWV0LCBjb25zZWN0ZXR1
ciBhZGlwaXNjaW5nIGVsaXQuLi5Mb3JlbSBpcHN1bSBkb2xvciBzaXQgYW1ldCwg
Y29uc2VjdGV0dXIgYWRpcGlzY2luZyBlbGl0Li4uTG9yZW0gaXBzdW0gZG9sb3Ig
c2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4uLkxvcmVtIGlw
c3VtIGRvbG9yIHNpdCBhbWV0LCBjb25zZWN0ZXR1ciBhZGlwaXNjaW5nIGVsaXQu
Li4K
-----END KEY1-----'''),
          PemPart('KEY', base64Encode('hello world!\n'.codeUnits)));
    });

    test('decodeLabelled', () {
      expect(
          PemPart.decodeLabelled('''-----BEGIN KEY-----
aGVsbG8gd29ybGQhCg==
-----END KEY-----
-----BEGIN KEY1-----
TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2Np
bmcgZWxpdC4uLkxvcmVtIGlwc3VtIGRvbG9yIHNpdCBhbWV0LCBjb25zZWN0ZXR1
ciBhZGlwaXNjaW5nIGVsaXQuLi5Mb3JlbSBpcHN1bSBkb2xvciBzaXQgYW1ldCwg
Y29uc2VjdGV0dXIgYWRpcGlzY2luZyBlbGl0Li4uTG9yZW0gaXBzdW0gZG9sb3Ig
c2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4uLkxvcmVtIGlw
c3VtIGRvbG9yIHNpdCBhbWV0LCBjb25zZWN0ZXR1ciBhZGlwaXNjaW5nIGVsaXQu
Li4K
-----END KEY1-----''', ['KEY1']),
          PemPart(
              'KEY1',
              base64Encode(
                  'Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...Lorem ipsum dolor sit amet, consectetur adipiscing elit...\n'
                      .codeUnits)));
    });
  });
}
