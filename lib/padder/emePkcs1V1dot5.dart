import 'dart:math';
import 'dart:typed_data';

import 'padder.dart';

class EmePkcs1V1dot5Encoder implements BlockPadder, IndividualBlockPadder {
  final Random rand;

  EmePkcs1V1dot5Encoder({Random rand}) : rand = rand ?? Random.secure();

  /// Pads a single block
  void padBlock(int blockSize, Iterable<int> block, ByteData output) {
    if (output.lengthInBytes != blockSize) {
      throw Exception('Invalid buffer size');
    }

    if (block.length > blockSize - 11) {
      throw Exception('block too long');
    }

    output.setUint8(0, 0);
    output.setUint8(1, 2);

    int i = 2;
    final psLen = blockSize - block.length - 3;
    for (int j = 0; j < psLen; j++) {
      int r = rand.nextInt(256);
      while (r == 0) {
        r = rand.nextInt(256);
      }
      output.setUint8(i++, r);
    }

    output.setUint8(i++, 0);

    for (int byte in block) {
      output.setUint8(i++, byte);
    }
  }

  Uint8List pad(int blockSize, Iterable<int> input) {
    int numBlocks = (input.length / (blockSize - 11)).ceil();
    final output = Uint8List(numBlocks * blockSize);

    for (int i = 0; i < numBlocks; i++) {
      Iterable<int> block;
      if (i == numBlocks - 1) {
        block = input;
      } else {
        block = input.take(blockSize - 11);
        input = input.skip(blockSize - 11);
      }
      padBlock(
          blockSize, block, output.buffer.asByteData(i * blockSize, blockSize));
    }

    return output;
  }

  Iterable<int> unpadBlock(int blockSize, Iterable<int> block) {
    if (block.length != blockSize) {
      throw Exception('Invalid blocksize');
    }

    if (block.elementAt(0) != 0) {
      throw Exception('Invalid block. First byte not 0');
    }

    if (block.elementAt(1) != 2) {
      throw Exception('Invalid block. Second byte not 2');
    }

    block = block.skip(2);

    block = block.skipWhile((v) => v != 0);

    if (block.isEmpty) {
      throw Exception('Invalid block. No Message delimiter found');
    }

    block = block.skip(1);

    // TODO is this an error?
    if (block.isEmpty) {
      throw Exception('Invalid block. No Message');
    }

    return block;
  }

  Iterable<int> unpad(int blockSize, Iterable<int> input) {
    if (input.length % blockSize != 0) {
      throw Exception(
          'Invalid message length. Must be multiple of blockSize $blockSize. Got ${input.length}');
    }

    final numBlocks = input.length ~/ blockSize;

    final out = Uint8List(numBlocks * (blockSize - 11));
    int outLen = 0;

    for (int i = 0; i < numBlocks; i++) {
      Iterable<int> block = input.take(blockSize);
      input = input.skip(blockSize);
      final unpaddedMsg = unpadBlock(blockSize, block);
      out.setAll(i * (blockSize - 11), unpaddedMsg);
      outLen += unpaddedMsg.length;
    }

    if (outLen == out.length) {
      return out;
    }

    return out.take(outLen);
  }
}
