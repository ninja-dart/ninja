import 'package:ninja/ninja.dart';
import 'package:test/scaffolding.dart';

void main() {
  group('RIPEMP160', () {
    test('convert', () {
      print(ripemd160.convert('abc'.codeUnits).asHex);
    });
  });
}
