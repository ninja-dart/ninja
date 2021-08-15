import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/src/hash_sink.dart';
import 'package:crypto/src/utils.dart';
import 'package:crypto/crypto.dart';

const RIPEMD160 ripemd160 = RIPEMD160._();

class RIPEMD160 extends Hash {
  final int blockSize = 64;

  const RIPEMD160._();

  ByteConversionSink startChunkedConversion(Sink<Digest> sink) =>
      ByteConversionSink.from(_RIPEMD160Sink(sink));
}

/// An instance of [RIPEMD160].
class _RIPEMD160Sink extends HashSink {
  _RIPEMD160Sink(Sink<Digest> sink) : super(sink, 16, endian: Endian.little) {
    digest[0] = 0x67452301;
    digest[1] = 0xefcdab89;
    digest[2] = 0x98badcfe;
    digest[3] = 0x10325476;
    digest[4] = 0xc3d2e1f0;
  }

  final Uint32List digest = Uint32List(5);

  @override
  void updateHash(Uint32List msg) {
    assert(msg.length == 16);

    var a = digest[0];
    var b = digest[1];
    var c = digest[2];
    var d = digest[3];
    var e = digest[4];

    var ah = a;
    var bh = b;
    var ch = c;
    var dh = d;
    var eh = e;

    for (var i = 0; i < 80; i++) {
      final t0 = (a + _f(i, b, c, d) + msg[_r[i]] + _K(i)) & mask32;
      final t1 = _rotl32(t0, _s[i]);
      var t = (t1 + e) & mask32;
      a = e;
      e = d;
      d = _rotl32(c, 10);
      c = b;
      b = t;
      t = (_rotl32(
                  (ah + _f(79 - i, bh, ch, dh) + msg[_rh[i]] + _Kh(i)) & mask32,
                  _sh[i]) +
              eh) &
          mask32;
      ah = eh;
      eh = dh;
      dh = _rotl32(ch, 10);
      ch = bh;
      bh = t;
    }

    var t = (digest[1] + c + dh) & mask32;
    digest[1] = (digest[2] + d + eh) & mask32;
    digest[2] = (digest[3] + e + ah) & mask32;
    digest[3] = (digest[4] + a + bh) & mask32;
    digest[4] = (digest[0] + b + ch) & mask32;
    digest[0] = t;
  }

  static const int _mask5 = 0x1F;

  /// rot left uint32
  int _rotl32(int x, int n) {
    return (_shiftl32(x, n)) | (x >> (32 - n) & mask32);
  }

  /// shift left uint32
  int _shiftl32(int x, int n) {
    n &= _mask5;
    x &= _mask32HiBits[n];
    return (x << n) & mask32;
  }

  final List<int> _mask32HiBits = [
    0xFFFFFFFF,
    0x7FFFFFFF,
    0x3FFFFFFF,
    0x1FFFFFFF,
    0x0FFFFFFF,
    0x07FFFFFF,
    0x03FFFFFF,
    0x01FFFFFF,
    0x00FFFFFF,
    0x007FFFFF,
    0x003FFFFF,
    0x001FFFFF,
    0x000FFFFF,
    0x0007FFFF,
    0x0003FFFF,
    0x0001FFFF,
    0x0000FFFF,
    0x00007FFF,
    0x00003FFF,
    0x00001FFF,
    0x00000FFF,
    0x000007FF,
    0x000003FF,
    0x000001FF,
    0x000000FF,
    0x0000007F,
    0x0000003F,
    0x0000001F,
    0x0000000F,
    0x00000007,
    0x00000003,
    0x00000001,
    0x00000000
  ];
}

/// f
int _f(int j, int x, int y, int z) {
  if (j <= 15) {
    return x ^ y ^ z;
  } else if (j <= 31) {
    return (x & y) | ((~x) & z);
  } else if (j <= 47) {
    return (x | (~y)) ^ z;
  } else if (j <= 63) {
    return (x & z) | (y & (~z));
  } else {
    return x ^ (y | (~z));
  }
}

/// K
int _K(int j) {
  if (j <= 15) {
    return 0x00000000;
  } else if (j <= 31) {
    return 0x5a827999;
  } else if (j <= 47) {
    return 0x6ed9eba1;
  } else if (j <= 63) {
    return 0x8f1bbcdc;
  } else {
    return 0xa953fd4e;
  }
}

/// Kh
int _Kh(int j) {
  if (j <= 15) {
    return 0x50a28be6;
  } else if (j <= 31) {
    return 0x5c4dd124;
  } else if (j <= 47) {
    return 0x6d703ef3;
  } else if (j <= 63) {
    return 0x7a6d76e9;
  } else {
    return 0x00000000;
  }
}

List<int> _r = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, //
  15, 3, 12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6,
  13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0,
  5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
];

List<int> _rh = [
  5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, //
  5, 10, 14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2,
  10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15,
  10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
];

List<int> _s = [
  11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, //
  9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8,
  13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
  9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
];

List<int> _sh = [
  8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, //
  8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13,
  5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15,
  8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
];
