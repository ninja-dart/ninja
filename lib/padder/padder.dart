import 'dart:typed_data';

export 'eme_oaep.dart';
export 'emePkcs1v15.dart';
export 'pkcs7.dart';

abstract class Padder {
  Uint8List pad(int blockSize, Iterable<int> input);

  Iterable<int> unpad(int blockSize, Iterable<int> input);
}

/// Can pad individual blocks separately
abstract class IndividualBlockPadder {
  void padBlock(int blockSize, Iterable<int> block, ByteData output);

  Iterable<int> unpadBlock(int blockSize, Iterable<int> block);
}

/// [Padder] that does not perform any padding.
class NopPadder implements Padder {
  Uint8List pad(int blockSize, Iterable<int> input) {
    if (input.length % blockSize != 0) {
      throw Exception('Input length must be multiple of blockSize: $blockSize');
    }

    return Uint8List.fromList(input);
  }

  Iterable<int> unpad(int blockSize, Iterable<int> input) {
    if (input.length % blockSize != 0) {
      throw Exception('Input length must be multiple of blockSize: $blockSize');
    }

    return input;
  }
}
