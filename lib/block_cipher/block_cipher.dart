import 'dart:typed_data';

export 'modes/cbc.dart';
export 'modes/ctr.dart';

abstract class BlockCipher {
  int get blockSize;

  int processBlock(ByteData input, ByteData output);
}
