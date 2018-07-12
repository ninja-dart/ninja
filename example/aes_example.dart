import 'dart:typed_data';
import 'package:ninja/ninja.dart';

main() {
  final aes = AES.fromBytes(Uint8List.fromList(List.generate(16, (i) => i)));
  String encoded = aes.encode('Dart');
  print(encoded);
  String decoded = aes.decode(encoded);
  print(decoded);
}
