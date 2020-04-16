import 'dart:typed_data';

import 'padder.dart';

class PKCS7Padder implements BlockPadder {
  const PKCS7Padder();

  Uint8List pad(int blockSize, Iterable<int> input) {
    if(blockSize > 255) {
      throw Exception('PKCS #7 only supports block sizes less than 256');
    }

    int numBlocks = (input.length + blockSize) ~/ blockSize;
    int outSize = numBlocks * blockSize;

    final ret = Uint8List(outSize);

    ret.setAll(0, input);
    for (int i = input.length; i < outSize; i++) {
      ret[i] = outSize - input.length;
    }

    return ret;
  }

  Iterable<int> unpad(int blockSize, Iterable<int> data) {
    if(blockSize > 255) {
      throw Exception('PKCS #7 only supports block sizes less than 256');
    }

    if (data.length % blockSize != 0) {
      throw ArgumentError('Data size must be multiple of $blockSize!');
    }

    if (data.last > blockSize) {
      throw ArgumentError.value(data, 'data', 'Invalid PKCS7 padding!');
    }

    final int pads = data.last;

    if (pads == blockSize) {
      if (data.length <= blockSize) {
        throw ArgumentError('Invalid PKCS7 padding!');
      }
    }

    return data.take(data.length - pads);
  }
}


