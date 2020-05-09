import 'dart:typed_data';
import 'package:ninja/ninja.dart';

main() {
  final aes = AESKey(Uint8List.fromList(List.generate(16, (i) => i)));
  String encoded = aes.encryptToBase64('Dart');
  print(encoded);
  String decoded = aes.decryptToUtf8(encoded);
  print(decoded);
}
