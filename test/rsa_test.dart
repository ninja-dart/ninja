import 'package:ninja/asymmetric/rsa/rsa.dart';
import 'package:test/test.dart';

void main() {
  group('rsa', () {
    group('RSAPublicKey', () {
      test('fromASN1', () {
        final key = RSAPublicKey.fromASN1(
            'MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANsFjQ22G36v8jGhcOtCnWtkuqqI9mWOq5I6Gy4NBb46ch2+gXL8/sC37X2BGASnt2YymAm7xwS2+QE89YYvDdECAwEAAQ==');
        expect(key.n.toString(),
            '11471096350072129820579819100426547181616187185658504704996065334930805271197099322753245009150228584617512330162571541229290378786994493391408050685808081');
        expect(key.e.toString(), '65537');
      });


    });
  });
}
