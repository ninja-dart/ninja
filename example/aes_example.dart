import 'dart:typed_data';
import 'package:ninja/ninja.dart';

main() {
  final aes = AESKey(Uint8List.fromList(List.generate(16, (i) => i)));
  String encoded = aes.encrypt('Dart');
  print(encoded);
  String decoded = aes.decrypt(encoded);
  print(decoded);
}
