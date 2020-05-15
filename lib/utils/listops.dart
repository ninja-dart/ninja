import 'dart:typed_data';

abstract class ListOps {
  static Uint8List xor(Iterable<int> a, Iterable<int> b) {
    if (a.length != b.length) {
      throw Exception('Lengths of a and b do not match');
    }

    final ret = Uint8List(a.length);

    final aIter = a.iterator;
    final bIter = b.iterator;
    for (int i = 0; i < ret.length; i++) {
      aIter.moveNext();
      bIter.moveNext();
      ret[i] = aIter.current ^ bIter.current;
    }

    return ret;
  }

  static Uint8List xorToByteData(ByteData a, Iterable<int> b) {
    if (a.lengthInBytes != b.length) {
      throw Exception('Lengths of a and b do not match');
    }

    int length = a.lengthInBytes;

    final bIter = b.iterator;
    for (int i = 0; i < length; i++) {
      bIter.moveNext();
      a.setUint8(i, a.getUint8(i) ^ bIter.current);
    }
  }
}
