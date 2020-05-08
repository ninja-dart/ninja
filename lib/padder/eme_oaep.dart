import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:ninja/padder/mgf/mgf.dart';
import 'package:ninja/padder/padder.dart';

class OAEPPadder implements BlockPadder, IndividualBlockPadder {
  final crypto.Hash hasher;

  final Mgf mgf;

  final Random random;

  OAEPPadder({crypto.Hash hasher, this.random, Mgf mgf})
      : hasher = hasher ?? crypto.sha1,
        mgf = mgf ?? mgf1Sha1;

  void padBlock(int blockSize, Iterable<int> block, ByteData output,
      {List<int> labelHash}) {
    final ps = List<int>.generate(
        blockSize - block.length - (2 * labelHash.length) - 2, (_) => 0);
    final db = <int>[...labelHash, ...ps, 0x01, ...block];

    final seed =
        List<int>.generate(labelHash.length, (_) => random.nextInt(255));
    final dbMask = mgf.encode(blockSize - labelHash.length - 1, seed);
    final maskedDb = List<int>.generate(
        blockSize - labelHash.length - 1, (i) => db[i] ^ dbMask[i]);

    final seedMask = mgf.encode(labelHash.length, maskedDb);
    final maskedSeed =
        List<int>.generate(labelHash.length, (i) => seed[i] ^ seedMask[i]);

    int index = 0;
    output.setUint8(index++, 0);
    for (int i = 0; i < maskedSeed.length; i++) {
      output.setUint8(index++, maskedSeed[i]);
    }
    for (int i = 0; i < maskedDb.length; i++) {
      output.setUint8(index++, maskedDb[i]);
    }
  }

  Uint8List pad(int blockSize, Iterable<int> input,
      {/* String | List<int> */ label = const <int>[]}) {
    if (label is! List<int>) {
      label = utf8.encode(label);
    }
    final labelHash = hasher.convert(label).bytes;

    int messageBlockSize = blockSize - (2 * labelHash.length) - 2;
    final int numMessageBlocks = (input.length / messageBlockSize).ceil();
    final output = Uint8List(numMessageBlocks * blockSize);

    for (int i = 0; i < numMessageBlocks; i++) {
      Iterable<int> block;
      if (i == numMessageBlocks - 1) {
        block = input;
      } else {
        block = input.take(messageBlockSize);
        input = input.skip(messageBlockSize);
      }
      padBlock(
          blockSize, block, output.buffer.asByteData(i * blockSize, blockSize));
    }

    return output;
  }

  Iterable<int> unpadBlock(int blockSize, Iterable<int> block) {
    // TODO
    throw UnimplementedError();
  }

  Iterable<int> unpad(int blockSize, Iterable<int> input) {
    // TODO
    throw UnimplementedError();
  }
}
