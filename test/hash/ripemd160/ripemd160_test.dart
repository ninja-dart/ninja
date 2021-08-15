import 'package:ninja/ninja.dart';
import 'package:test/expect.dart';
import 'package:test/scaffolding.dart';

class TestCase {
  final Map<String, String> hashes;

  TestCase(this.hashes);

  void perform() {
    for (final msg in hashes.keys) {
      final hash = ripemd160.convert(msg.codeUnits).asHex;
      expect(hash, hashes[msg]);
    }
  }
}

void main() {
  group('RIPEMP160', () {
    test('bosselae_testvector', () {
      final tc = TestCase({
        "": "9c1185a5c5e9fc54612808977ee8f548b2258d31",
        "a": "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe",
        "abc": "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
        "message digest": "5d0689ef49d2fae572b881b123a85ffa21595f36",
        "abcdefghijklmnopqrstuvwxyz":
            "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq":
            "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789":
            "b0e20b6e3116640286ed3a87a5713079b21f5189",
        "1234567890" * 8: "9b752e45573d4b39f4dbd3323cab82bf63326bfb",
        'a' * 1000000: '52783243c1697bdbe16d37f97f68f08325dc1528',
      });
      tc.perform();
    });
    test('64bytes', () {
      final tc = TestCase({
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890^_':
            '1ee2a4b162e4dc733b4eaa8b014369846af51c5c',
        '''ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890^_abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq()+?#'"!''':
            '577c3cde4a49053e808d9332e2ca697818023218',
      });
      tc.perform();
    });
  });
}
