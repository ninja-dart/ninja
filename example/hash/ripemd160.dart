import 'package:ninja/hash/hash.dart';

void perform(String msg) {
  var hash = ripemd160.convert(msg.codeUnits).asHex;
  print(hash);
}

void main() {
  // perform('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890^_');
  perform('''ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890^_abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq()+?#'"!''');
}
