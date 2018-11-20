part of 'rsa.dart';

// [RSAEncryptionEngine] and [RSADecryptionEngine] are copied and modified from
// pointy_castles package. See file LICENSE/pointy_castle_LICENSE
// file for more information.

class RSAEncryptionEngine {
  final RSAPublicKey key;

  final int inputBlockSize;

  final int outputBlockSize;

  RSAEncryptionEngine(this.key)
      : inputBlockSize = ((key.n.bitLength + 7) ~/ 8) - 1,
        outputBlockSize = (key.n.bitLength + 7) ~/ 8;

  Uint8List process(Uint8List data) {
    var out = Uint8List(outputBlockSize);
    int len = processBlock(data, 0, data.length, out, 0);
    return out.sublist(0, len);
  }

  int processBlock(
      Uint8List inp, int inpOff, int len, Uint8List out, int outOff) {
    var input = _convertInput(inp, inpOff, len);
    BigInt output = input.modPow(key.e, key.n);
    return _convertOutput(output, out, outOff);
  }

  BigInt _convertInput(Uint8List inp, int inpOff, int len) {
    int inpLen = inp.length;

    if (inpLen > (inputBlockSize + 1))
      throw ArgumentError("Input too large for RSA cipher");

    BigInt res = decodeBigInt(inp.sublist(inpOff, inpOff + len));
    if (res >= key.n) throw ArgumentError("Input too large for RSA cipher");

    return res;
  }

  int _convertOutput(BigInt result, Uint8List out, int outOff) {
    final Uint8List output = encodeBigInt(result);

    if ((output[0] == 0) && (output.length > outputBlockSize)) {
      // have ended up with an extra zero byte, copy down.
      var len = (output.length - 1);
      out.setRange(outOff, outOff + len, output.sublist(1));
      return len;
    }
    if (output.length < outputBlockSize) {
      // have ended up with less bytes than normal, lengthen
      var len = outputBlockSize;
      out.setRange((outOff + len - output.length), (outOff + len), output);
      return len;
    }

    out.setAll(outOff, output);
    return output.length;
  }
}

class RSADecryptionEngine {
  final RSAPrivateKey _key;
  BigInt _dP;
  BigInt _dQ;
  BigInt _qInv;

  final int inputBlockSize;

  final int outputBlockSize;

  RSADecryptionEngine(this._key)
      : inputBlockSize = (_key.n.bitLength + 7) ~/ 8,
        outputBlockSize = ((_key.n.bitLength + 7) ~/ 8) - 1 {
    BigInt pSub1 = (_key.p - BigInt.one);
    BigInt qSub1 = (_key.q - BigInt.one);
    _dP = _key.d.remainder(pSub1);
    _dQ = _key.d.remainder(qSub1);
    _qInv = _key.q.modInverse(_key.p);
  }

  Uint8List process(Uint8List data) {
    var out = Uint8List(outputBlockSize);
    int len = processBlock(data, 0, data.length, out, 0);
    return out.sublist(0, len);
  }

  int processBlock(
      Uint8List inp, int inpOff, int len, Uint8List out, int outOff) {
    BigInt input = _convertInput(inp, inpOff, len);
    BigInt output = _processBigInteger(input);
    return _convertOutput(output, out, outOff);
  }

  BigInt _convertInput(Uint8List inp, int inpOff, int len) {
    var inpLen = inp.length;

    if (inpLen > (inputBlockSize + 1))
      throw ArgumentError("Input too large for RSA cipher");

    if ((inpLen == (inputBlockSize + 1)))
      throw ArgumentError("Input too large for RSA cipher");

    BigInt res = decodeBigInt(inp.sublist(inpOff, inpOff + len));
    if (res >= _key.n) throw ArgumentError("Input too large for RSA cipher");

    return res;
  }

  int _convertOutput(BigInt result, Uint8List out, int outOff) {
    final Uint8List output = encodeBigInt(result);

    if (output[0] == 0) {
      // Have ended up with an extra zero byte, copy down.
      int len = output.length - 1;
      out.setRange(outOff, outOff + len, output.sublist(1));
      return len;
    }

    out.setAll(outOff, output);
    return output.length;
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
