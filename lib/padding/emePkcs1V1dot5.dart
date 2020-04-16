import 'dart:math';
import 'dart:typed_data';

import 'padding.dart';

class EmePkcs1V1dot5Encoder implements Padder {
  final int blockSize;

  final Random rand;

  EmePkcs1V1dot5Encoder(this.blockSize, {Random rand}): rand = rand ?? Random.secure();

  /// Pads a single block
  void padBlock(Iterable<int> block, ByteData output) {
    if(output.lengthInBytes != blockSize) {
      throw Exception('Invalid buffer size');
    }

    if(block.length > blockSize - 11) {
      throw Exception('block too long');
    }

    output.setUint8(0, 0);
    output.setUint8(1, 2);

    int i = 2;
    final psLen = blockSize - block.length - 3;
    for(; i < psLen; i++) {
      int r = rand.nextInt(256);
      while(r == 0) {
        r = rand.nextInt(256);
      }
      output.setUint8(i, r);
    }

    output.setUint8(i++, 0);

    output.buffer.asUint8List(i).setAll(0, block);
  }

  Uint8List pad(Iterable<int> input) {
    int numBlocks = (input.length/(blockSize - 11)).ceil();
    final output = Uint8List(numBlocks * blockSize);

    for(int i = 0; i < numBlocks; i++) {
      Iterable<int> block;
      if(i == numBlocks - 1) {
        block = input;
      } else {
        block = input.take(blockSize - 11);
        input = input.skip(blockSize - 11);
      }
      padBlock(block, output.buffer.asByteData(i * blockSize, blockSize));
    }

    return output;
  }

  Iterable<int> unpadBlock(Iterable<int> block) {
    if(block.length != blockSize) {
      throw Exception('Invalid blocksize');
    }

    if(block.elementAt(0) != 0) {
      throw Exception('Invalid block. First byte not 0');
    }

    if(block.elementAt(1) != 2) {
      throw Exception('Invalid block. Second byte not 2');
    }

    block = block.skip(2);

    block.skipWhile((v) => v != 0);

    if(block.isEmpty) {
      throw Exception('Invalid block. No Message delimiter found');
    }

    block.skip(1);

    // TODO is this an error?
    if(block.isEmpty) {
      throw Exception('Invalid block. No Message');
    }

    return block;
  }

  Iterable<int> unpad(Iterable<int> input) {
    if(input.length % blockSize != 0) {
      throw Exception('Invalid message length. Must be multiple of blockSize $blockSize');
    }

    final numBlocks = input.length ~/ blockSize;

    final out = Uint8List(numBlocks * blockSize);
    int outLen = 0;

    for(int i = 0; i < numBlocks; i++) {
      Iterable<int> block = input.take(blockSize);
      input = input.skip(blockSize);
      final unpaddedMsg = unpadBlock(block);
      out.setAll(i * blockSize, unpaddedMsg);
      outLen += unpaddedMsg.length;
    }

    if(outLen == out.length) return out;

    return out.take(outLen);
  }
}
