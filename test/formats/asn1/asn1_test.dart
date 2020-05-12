import 'package:ninja/formats/asn1/asn1.dart';
import 'package:ninja/ninja.dart';
import 'package:test/test.dart';

void main() {
  group('ASN1', () {
    test('ASN1Sequence.encode', () {
      expect(hexEncode(ASN1Sequence(
              [ASN1Integer(BigInt.from(5)), ASN1Null(), ASN1Boolean(true)])
          .encode()), '300802010505000101ff');
    });
  });
}
