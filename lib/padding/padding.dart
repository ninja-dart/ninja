import 'dart:typed_data';

abstract class Padded {
  int get blockSize;

  int get totalBlocks;

  int get totalBytes;

  Uint8List operator [](int index);
}

abstract class Padder {
  Padded pad(int blockSize, Uint8List data);
  Uint8List unpad(int blockSize, Uint8List data);
}
