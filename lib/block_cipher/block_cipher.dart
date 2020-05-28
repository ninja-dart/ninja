import 'dart:typed_data';

export 'modes/cbc.dart';

abstract class BlockCipher {
  int get blockSize;

  int processBlock(ByteData input, ByteData output);
}
