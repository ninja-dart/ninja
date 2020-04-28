import 'package:ninja/utils/big_int.dart';
import 'package:test/test.dart';

void main() {
  group('bigint', () {
    test('base64ToBigInt', () {
      expect(base64ToBigInt('AQAB').toString(), '65537');
      expect(
          base64ToBigInt(
                  '2wWNDbYbfq/yMaFw60Kda2S6qoj2ZY6rkjobLg0FvjpyHb6Bcvz+wLftfYEYBKe3ZjKYCbvHBLb5ATz1hi8N0Q==')
              .toString(),
          '11471096350072129820579819100426547181616187185658504704996065334930805271197099322753245009150228584617512330162571541229290378786994493391408050685808081');
    });
  });
}
