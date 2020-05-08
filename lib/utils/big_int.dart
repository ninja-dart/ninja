import 'dart:convert';
import 'dart:typed_data';

// This file has been copied and modified from pointy_castles package. See file
// LICENSE/pointy_castle_LICENSE file for more information.

/// Decode a BigInt from bytes in big-endian encoding.
/// This is OS2IP as defined in rfc3447.
BigInt bytesToBigInt(Iterable<int> bytes) {
  BigInt result = BigInt.from(0);

  for (int byte in bytes) {
    result = result << 8;
    result |= BigInt.from(byte);
  }

  return result;
}

/// Encode a BigInt into bytes using big-endian encoding.
/// This is I2OSP as defined in rfc3447.
Uint8List bigIntToBytes(BigInt number, {int outLen}) {
  int size = (number.bitLength + 7) >> 3;
  if (outLen == null) {
    outLen = size;
  } else if (outLen < size) {
    throw Exception('Number too large');
  }
  final result = Uint8List(outLen);
  int pos = outLen - 1;
  for (int i = 0; i < size; i++) {
    result[pos--] = (number & _byteMask).toInt();
    number = number >> 8;
  }
  return result;
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
