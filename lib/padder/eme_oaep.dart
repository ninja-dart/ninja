import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:ninja/padder/mgf/mgf.dart';
import 'package:ninja/padder/padder.dart';
import 'package:ninja/utils/iterable.dart';

final sha1OaepPadder = OAEPPadder();

class OAEPPadder implements Padder, IndividualBlockPadder {
  final crypto.Hash hasher;

  final Mgf mgf;

  final Random random;

  OAEPPadder({crypto.Hash hasher, Random random, Mgf mgf})
      : random = random ?? Random.secure(),
        hasher = hasher ?? crypto.sha1,
        mgf = mgf ?? mgf1Sha1;

  void padBlock(int blockSize, Iterable<int> block, ByteData output,
      {List<int> labelHash, /* String | List<int> */ label}) {
    if (labelHash == null) {
      if (label == null) label = <int>[];

      labelHash = hasher.convert(label).bytes;
    }

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

  Iterable<int> unpadBlock(int blockSize, Iterable<int> block,
      {List<int> labelHash, /* String | List<int> */ label}) {
    if (block.length != blockSize) {
      throw Exception('Invalid blocksize');
    }

    if (block.elementAt(0) != 0) {
      throw Exception('Invalid block. First byte not 0');
    }

    if (labelHash == null) {
      if (label == null) label = <int>[];

      labelHash = hasher.convert(label).bytes;
    }

    final maskedSeed = block.skip(1).take(labelHash.length).toList();
    final maskedDb = block.skip(1 + labelHash.length).toList();

    final seedMask = mgf.encode(labelHash.length, maskedDb);
    final seed = List<int>.generate(
        labelHash.length, (i) => seedMask[i] ^ maskedSeed[i]);

    final dbMask = mgf.encode(blockSize - labelHash.length - 1, seed);
    Iterable<int> db = List<int>.generate(
        blockSize - labelHash.length - 1, (i) => dbMask[i] ^ maskedDb[i]);

    final labelHashDash = db.take(labelHash.length);
    if (!iterableEquality.equals(labelHash, labelHashDash)) {
      throw Exception('Invalid block. Label hashes do not match');
    }
    db = db.skip(labelHash.length);

    db = db.skipWhile((value) => value == 0);

    if (db.isEmpty) {
      throw Exception('Invalid block. No delimiter');
    }

    if (db.first != 0x01) {
      throw Exception('Invalid block. Invalid delimiter');
    }

    return db.skip(1);
  }

  Iterable<int> unpad(int blockSize, Iterable<int> input,
      {/* String | List<int> */ label = const <int>[]}) {
    if (label is! List<int>) {
      label = utf8.encode(label);
    }
    final labelHash = hasher.convert(label).bytes;
    if (input.length % blockSize != 0) {
      throw Exception(
          'Invalid message length. Must be multiple of blockSize $blockSize. Got ${input.length}');
    }

    int messageBlockSize = blockSize - (2 * labelHash.length) - 2;
    final numBlocks = input.length ~/ blockSize;

    final out = Uint8List(numBlocks * messageBlockSize);
    int outLen = 0;

    for (int i = 0; i < numBlocks; i++) {
      Iterable<int> block = input.take(blockSize);
      input = input.skip(blockSize);
      final unpaddedMsg = unpadBlock(blockSize, block, labelHash: labelHash);
      out.setAll(i * messageBlockSize, unpaddedMsg);
      outLen += unpaddedMsg.length;
    }

    if (outLen == out.length) {
      return out;
    }

    return out.take(outLen);
  }
}
