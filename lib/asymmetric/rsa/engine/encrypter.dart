// [RSAEncryptionEngine] and [RSADecryptionEngine] are copied and modified from
// pointy_castles package. See file LICENSE/pointy_castle_LICENSE
// file for more information.

import 'dart:convert';
import 'dart:typed_data';

import 'package:ninja/asymmetric/rsa/rsa.dart';
import 'package:ninja/utils/big_int.dart';

class RSAEncryptionEngine {
  final RSAPublicKey key;

  final int blockSize;

  final int bitSize;

  RSAEncryptionEngine(this.key)
      : bitSize = key.n.bitLength,
        blockSize = (key.n.bitLength + 7) ~/ 8;

  Iterable<int> process(Iterable<int> data) {
    final numBlocks = (data.length / blockSize).ceil();
    final out = Uint8List(numBlocks * blockSize);
    int outOffset = 0;
    for (int i = 0; i < numBlocks; i++) {
      Iterable<int> curInputBlock;
      if (i == numBlocks - 1) {
        curInputBlock = data;
      } else {
        curInputBlock = data.take(blockSize);
      }
      outOffset += processBlock(curInputBlock, out, outOffset);
      data = data.skip(blockSize);
    }

    return out;
  }

  int processBlock(Iterable<int> inputBlock, Uint8List out, int outOff) {
    final input = _convertInput(inputBlock);
    BigInt output = input.modPow(key.e, key.n);
    return _convertOutput(output, out, outOff);
  }

  List<int> unsign(final /* BigInt | Iterable<int> | String */ message) {
    BigInt input;
    if (message is BigInt) {
      input = message;
    } else if (message is Iterable<int>) {
      input = _convertInput(message);
    } else if (message is String) {
      input = _convertInput(base64Decode(message));
    } else {
      throw ArgumentError('Unknown type');
    }
    final signedBigInt = input.modPow(key.e, key.n);
    final ret = bigIntToBytes(signedBigInt, outLen: blockSize);
    return ret;
  }

  BigInt _convertInput(Iterable<int> input) {
    if (input.length > blockSize) {
      throw ArgumentError("Input too large for RSA cipher");
    }

    BigInt res = bytesToBigInt(input);
    if (res >= key.n) throw ArgumentError("Input too large for RSA cipher");

    return res;
  }

  int _convertOutput(BigInt result, Uint8List out, int offset) {
    final Uint8List output = bigIntToBytes(result);
    out.setAll(offset + (blockSize - output.length), output);
    return blockSize;
  }
}
