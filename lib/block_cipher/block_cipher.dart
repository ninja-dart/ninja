import 'dart:typed_data';

abstract class BlockCipher {
  int get blockSize;

  int processBlock(ByteData input, ByteData output);
}
