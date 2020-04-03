import 'dart:typed_data';
import 'padding.dart';

class PKCS7Padded implements Padded {
  final int blockSize;

  final Uint8List _data;

  final int totalBlocks;

  final int totalBytes;

  PKCS7Padded._(this.blockSize, this._data, this.totalBlocks, this.totalBytes);

  factory PKCS7Padded(int blockSize, Uint8List data) {
    int totalBlocks;

    if (data.length % blockSize == 0) {
      totalBlocks = (data.length ~/ blockSize) + 1;
    } else {
      totalBlocks = (data.length + blockSize) ~/ blockSize;
    }

    return PKCS7Padded._(blockSize, data, totalBlocks, totalBlocks * blockSize);
  }

  Uint8List operator [](int index) {
    if (index >= totalBlocks) throw RangeError.range(index, 0, totalBlocks - 1);

    if (index < (totalBlocks - 1)) {
      return Uint8List.view(_data.buffer, index * blockSize, blockSize);
    }

    if (_data.length % blockSize == 0) {
      var ret = Uint8List(blockSize);
      for (int i = 0; i < blockSize; i++) {
        ret[i] = blockSize;
      }
      return ret;
    } else {
      var ret = Uint8List(blockSize);
      int offset = index * blockSize;
      int j = 0;
      for (int i = offset; i < _data.length; i++) {
        ret[j++] = _data[i];
      }
      int pad = blockSize - _data.length - offset;
      for (; j < blockSize; j++) {
        ret[j] = pad;
      }
      return ret;
    }
  }
}

class PKCS7Padder implements Padder {
  const PKCS7Padder();

  PKCS7Padded pad(int blockSize, Uint8List data) =>
      PKCS7Padded(blockSize, data);

  Uint8List unpad(int blockSize, Uint8List data) {
    if (data.isEmpty) return data;
    if (data.length % blockSize != 0) {
      throw ArgumentError.value(
          data, 'data', 'Data size must be multiple of $blockSize!');
    }

    if (data.last == blockSize) {
      if (data.length < blockSize) {
        throw ArgumentError.value(data, 'data', 'Invalid PKCS7 padding!');
      }

      return Uint8List.view(data.buffer, 0, data.length - blockSize);
    }

    if (data.last > blockSize) {
      throw ArgumentError.value(data, 'data', 'Invalid PKCS7 padding!');
    }

    int pads = data.last;
    return Uint8List.view(data.buffer, 0, data.length - pads);
  }
}
