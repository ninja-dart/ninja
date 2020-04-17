import 'dart:convert';
import 'dart:typed_data';

import 'package:ninja/asymmetric/rsa/rsa.dart';
import 'package:ninja/utils/big_int.dart';

class RSADecryptionEngine {
  final RSAPrivateKey _key;
  BigInt _dP;
  BigInt _dQ;
  BigInt _qInv;

  final int blockSize;

  final int bitSize;

  RSADecryptionEngine(this._key)
      : bitSize = _key.n.bitLength,
        blockSize = (_key.n.bitLength + 7) >> 3 {
    BigInt pSub1 = (_key.p - BigInt.one);
    BigInt qSub1 = (_key.q - BigInt.one);
    _dP = _key.d.remainder(pSub1);
    _dQ = _key.d.remainder(qSub1);
    _qInv = _key.q.modInverse(_key.p);
  }

  Iterable<int> process(Iterable<int> data, {bool dontPadLastBlock = false}) {
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
      if (dontPadLastBlock && i == numBlocks - 1) {
        int outBlockLen = processBlock(curInputBlock, out, outOffset,
            dontPad: dontPadLastBlock);
        outOffset += outBlockLen;
      } else {
        processBlock(curInputBlock, out, outOffset);
        outOffset += blockSize;
      }
      data = data.skip(blockSize);
    }

    if (!dontPadLastBlock || outOffset == out.length) {
      return out;
    }

    return out.sublist(0, outOffset);
  }

  int processBlock(Iterable<int> inputBlock, Uint8List out, int outOff,
      {bool dontPad = false}) {
    BigInt input = _convertInput(inputBlock);
    BigInt output = _processBigInteger(input);
    return _convertOutput(output, out, outOff, dontPad: dontPad);
  }

  List<int> signBlock(final /* BigInt | Iterable<int> | String */ message) {
    BigInt input;
    if (message is BigInt) {
      input = message;
    } else if (message is Iterable<int>) {
      input = _convertInput(message);
    } else if (message is String) {
      input = _convertInput(utf8.encode(message));
    } else {
      throw ArgumentError('Unknown type');
    }
    final signedBigInt = input.modPow(_key.d, _key.n);
    return bigIntToBytes(signedBigInt);
  }

  BigInt _convertInput(Iterable<int> input) {
    if (input.length > blockSize) {
      throw ArgumentError("Input too large for RSA cipher");
    }

    BigInt res = bytesToBigInt(input);
    if (res >= _key.n) throw ArgumentError("Input too large for RSA cipher");

    return res;
  }

  int _convertOutput(BigInt result, Uint8List out, int outOff,
      {bool dontPad = false}) {
    final Uint8List output = bigIntToBytes(result);
    if (dontPad || output.length == blockSize) {
      out.setAll(outOff, output);
      return output.length;
    }
    out.setAll(outOff + (blockSize - output.length), output);
    return blockSize;
  }

  BigInt _processBigInteger(BigInt input) {
    BigInt mP = (input.remainder(_key.p)).modPow(_dP, _key.p);

    BigInt mQ = (input.remainder(_key.q)).modPow(_dQ, _key.q);

    BigInt h = mP - mQ;
    h = h * _qInv;
    h = h % _key.p;

    BigInt m = h * _key.q;
    m = m + mQ;

    return m;
  }
}
