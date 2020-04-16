import 'dart:typed_data';

abstract class Padder {
  Uint8List pad(Iterable<int> input);

  Iterable<int> unpad(Iterable<int> input);
}
