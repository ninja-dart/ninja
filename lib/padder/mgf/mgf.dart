import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:ninja/utils/big_int.dart';

abstract class Mgf {
  List<int> encode(int blockSize, Iterable<int> input);
}

class Mgf1 implements Mgf {
  final crypto.Hash hasher;

  Mgf1({crypto.Hash? hasher}) : hasher = hasher ?? crypto.sha1;

  Uint8List encode(int blockSize, Iterable<int> input) {
    final inputLen = input.length;
    final output = Uint8List(blockSize);

    final inputBlock = Uint8List(inputLen + 4);
    inputBlock.setRange(0, inputLen, input);

    int i = 0;
    int offset = 0;
    while (offset < blockSize) {
      BigInt counter = BigInt.from(i);
      inputBlock.setRange(
          inputLen, inputLen + 4, bigIntToBytes(counter, outLen: 4));

      final outputBlock = hasher.convert(inputBlock).bytes;
      int end = offset + outputBlock.length;
      if (end > blockSize) {
        end = blockSize;
      }
      output.setRange(offset, end, outputBlock);
      offset = end;

      i++;
    }

    return output;
  }
}

final mgf1Sha1 = Mgf1(hasher: crypto.sha1);

final mgf1Sha256 = Mgf1(hasher: crypto.sha256);
