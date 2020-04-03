import 'dart:convert';
import 'dart:typed_data';

// This file has been copied and modified from pointy_castles package. See file
// LICENSE/pointy_castle_LICENSE file for more information.

/// Decode a BigInt from bytes in big-endian encoding.
BigInt bytesToBigInt(List<int> bytes) {
  BigInt result = BigInt.from(0);
  for (int i = 0; i < bytes.length; i++) {
    result += BigInt.from(bytes[bytes.length - i - 1]) << (8 * i);
  }
  return result;
}

/// Encode a BigInt into bytes using big-endian encoding.
Uint8List bigIntToBytes(BigInt number) {
  // Not handling negative numbers. Decide how you want to do that.
  int size = (number.bitLength + 7) >> 3;
  var result = Uint8List(size);
  for (int i = 0; i < size; i++) {
    result[size - i - 1] = (number & _byteMask).toInt();
    number = number >> 8;
  }
  return result;
}

final _byteMask = BigInt.from(0xff);

BigInt base64ToBigInt(String input) {
  final bytes = base64.decode(input);
  return bytesToBigInt(bytes);
}

String bigIntToBase64(BigInt input) {
  final bytes = bigIntToBytes(input);
  return base64.encode(bytes);
}