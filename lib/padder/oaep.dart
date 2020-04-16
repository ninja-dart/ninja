import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:ninja/padder/padder.dart';

class OAEPPadder implements BlockPadder, IndividualBlockPadder {
  final Digest hasher;

  final Random random;

  OAEPPadder({Digest hasher, this.random}) : hasher = hasher ?? sha1;

  void padBlock(int blockSize, Iterable<int> block, ByteData output) {
    // TODO
    throw UnimplementedError();
  }

  Uint8List pad(int blockSize, Iterable<int> input) {
    // TODO
    throw UnimplementedError();
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
