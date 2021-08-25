import 'dart:convert';
import 'dart:typed_data';

import 'package:ninja_hex/ninja_hex.dart';

/// Decodes the provided [BigInt] from bytes.
/// This is OS2IP as defined in rfc3447.
BigInt bytesToBigInt(Iterable<int> bytes, {Endian endian = Endian.big}) {
  BigInt result = BigInt.from(0);
  if (endian == Endian.little) {
    bytes = bytes.toList().reversed;
  }

  for (int byte in bytes) {
    result = result << 8;
    result |= BigInt.from(byte);
  }

  return result;
}

/// Encode a BigInt into bytes using big-endian encoding.
/// This is I2OSP as defined in rfc3447.
Uint8List bigIntToBytes(BigInt number,
    {int? outLen, Endian endian = Endian.big}) {
  int size = (number.bitLength + 7) >> 3;
  if (outLen == null) {
    outLen = size;
  } else if (outLen < size) {
    throw Exception('Number too large');
  }
  final result = Uint8List(outLen);
  int pos = endian == Endian.big ? outLen - 1 : 0;
  for (int i = 0; i < size; i++) {
    result[pos] = (number & _byteMask).toInt();
    if (endian == Endian.big) {
      pos -= 1;
    } else {
      pos += 1;
    }
    number = number >> 8;
  }
  return result;
}

extension BigIntUint8List on BigInt {
  Uint8List asBytes({int? outLen, Endian endian = Endian.big}) =>
      bigIntToBytes(this, outLen: outLen, endian: endian);
}

extension Uint8ListBigInt on Iterable<int> {
  BigInt asBigInt({Endian endian = Endian.big}) =>
      bytesToBigInt(this, endian: endian);

  String toHex({int? outLen, Endian endian = Endian.big}) =>
      (endian == Endian.big ? this : this.toList().reversed)
          .map((e) => e.hexByte)
          .join()
          .padLeft(outLen ?? 0, '0');
}

// Not handling negative numbers. Decide how you want to do that.

final _byteMask = BigInt.from(0xff);

BigInt base64ToBigInt(String input) {
  final bytes = base64.decode(input);
  return bytesToBigInt(bytes);
}

String bigIntToBase64(BigInt input) {
  final bytes = bigIntToBytes(input);
  return base64.encode(bytes);
}

String intStringToHex(String input) {
  return hexEncode(bigIntToBytes(BigInt.parse(input)));
}

String hexToIntString(String input) {
  return bytesToBigInt(hexDecode(input)).toRadixString(10);
}

String bigIntToHex(BigInt input) {
  return hexEncode(bigIntToBytes(input));
}

BigInt hexToBigInt(String input) {
  return bytesToBigInt(hexDecode(input));
}

extension IntHex on int {
  String get hexByte {
    if (this > 255) {
      throw Exception('invalid byte value. must be <= 255');
    }
    return toRadixString(16).padLeft(2, '0');
  }
}
