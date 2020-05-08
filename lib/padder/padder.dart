import 'dart:typed_data';

export 'emePkcs1V15.dart';
export 'eme_oaep.dart';
export 'pkcs7.dart';

abstract class BlockPadder {
  Uint8List pad(int blockSize, Iterable<int> input);

  Iterable<int> unpad(int blockSize, Iterable<int> input);
}

/// Can pad individual blocks separately
abstract class IndividualBlockPadder {
  void padBlock(int blockSize, Iterable<int> block, ByteData output);

  Iterable<int> unpadBlock(int blockSize, Iterable<int> block);
}