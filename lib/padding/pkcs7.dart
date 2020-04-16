import 'dart:typed_data';

import 'padding.dart';

class PKCS7Padder implements Padder {
  final int blockSize;

  PKCS7Padder(this.blockSize) {
    if(blockSize > 255) {
      throw Exception('PKCS #7 only supports block sizes less than 256');
    }
  }

  Uint8List pad(Iterable<int> input) {
    int numBlocks = (input.length + blockSize) ~/ blockSize;
    int outSize = numBlocks * blockSize;

    final ret = Uint8List(outSize);

    ret.setAll(0, input);
    for (int i = input.length; i < outSize; i++) {
      ret[i] = outSize - input.length;
    }

    return ret;
  }

  Iterable<int> unpad(Iterable<int> data) {
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


