import 'dart:typed_data';

import 'package:ninja/utils/big_int.dart';

class ASN1Type {
  final int tag;

  final String name;

  const ASN1Type(this.tag, this.name);

  bool operator ==(other) {
    if (other is ASN1Type) {
      return other.tag == tag;
    } else if (other is int) {
      return other == tag;
    }

    return false;
  }

  static const booleanTag = 0x01;
  static const integerTag = 2;
  static const bitStringTag = 3;
  static const octetStringTag = 4;
  static const nullTag = 5;
  static const objectIdentifierTag = 6;
  static const sequenceTag = 0x30;
  static const setTag = 0x31;
  static const printableStringTag = 19;
  static const T61StringTag = 20;
  static const IA5StringTag = 22;
  static const UTCTimeTag = 23;
}

class ASN1DecodedLength {
  final BigInt length;

  final int bytesRequired;

  ASN1DecodedLength(this.length, this.bytesRequired);

  int get lengthAsInt {
    if(!length.isValidInt) {
      throw Exception('Length too large');
    }

    return length.toInt();
  }
}

abstract class ASN1Object {
  int get tag;

  Uint8List encode();

  static List<int> encodeLength(int length) {
    if (length <= 127) {
      return <int>[length];
    }
    final bytes = bigIntToBytes(BigInt.from(length));
    return <int>[
      bytes.length | 0x80,
      ...bytes,
    ];
  }

  static ASN1DecodedLength decodeLength(Iterable<int> input) {
    if(input.isEmpty) {
      throw Exception('Invalid data');
    }

    if((input.first & 0x80) == 0) {
      return ASN1DecodedLength(BigInt.from(input.first), 1);
    }

    int numBytes = input.first & 0x7F;
    input = input.skip(1);
    if(input.length < numBytes) {
      throw Exception('Invalid data');
    }
    final ret = bytesToBigInt(input.take(numBytes));

    return ASN1DecodedLength(ret, numBytes + 1);
  }

  static Uint8List pack(int tag, Iterable<int> content) {
    // TODO check tag is octect

    final encodedLength = ASN1Object.encodeLength(content.length);

    final ret = Uint8List(1 + encodedLength.length + content.length);
    ret[0] = tag;
    ret.setRange(1, 1 + encodedLength.length, encodedLength);
    ret.setRange(1 + encodedLength.length, ret.length, content);

    return ret;
  }
}

class ASN1Sequence implements ASN1Object {
  final int tag = ASN1Type.sequenceTag;

  final List<ASN1Object> children;

  ASN1Sequence(Iterable<ASN1Object> children)
      : children = List<ASN1Object>.from(children);

  Uint8List encode() {
    List<int> content = children.map((e) => e.encode()).fold(
        <int>[], (previousValue, element) => previousValue..addAll(element));

    return ASN1Object.pack(tag, content);
  }
}

class ASN1Boolean implements ASN1Object {
  final int tag = ASN1Type.booleanTag;

  bool value;

  ASN1Boolean(this.value);

  factory ASN1Boolean.decode(Iterable<int> bytes) {
    if(bytes.length < 3) {
      throw Exception('Invalid data!');
    }

    int tag = bytes.first;
    if(tag != ASN1Type.booleanTag) {
      throw Exception('Invalid tag!');
    }
    bytes = bytes.skip(1);

    if(bytes.first != 1) {
      throw Exception('Invalid length!');
    }
    bytes = bytes.skip(1);

    return ASN1Boolean(bytes.first != 0);
  }

  Uint8List encode() {
    final ret = Uint8List(3);
    ret[0] = tag;
    ret[1] = 1;
    ret[2] = value ? 0xFF : 0x00;

    return ret;
  }
}

class ASN1Integer implements ASN1Object {
  final int tag = ASN1Type.integerTag;

  BigInt value;

  ASN1Integer(this.value);

  ASN1Integer.fromNum(num value): value = BigInt.from(value);

  factory ASN1Integer.decode(Iterable<int> bytes) {
    if(bytes.length < 3) {
      throw Exception('Invalid data!');
    }

    int tag = bytes.first;
    if(tag != ASN1Type.booleanTag) {
      throw Exception('Invalid tag!');
    }
    bytes = bytes.skip(1);

    final decodedLength = ASN1Object.decodeLength(bytes);
    int length = decodedLength.lengthAsInt;
    if(length == 0) {
      throw Exception('Invalid data');
    }
    bytes = bytes.skip(decodedLength.bytesRequired);

    if(bytes.length < length) {
      throw Exception('Invalid data');
    }

    bytes = bytes.take(length);

    BigInt value = bytesToBigInt(bytes);
    if((bytes.first & 0x80) == 0) {
      value = value.toSigned(value.bitLength);
    }

    return ASN1Integer(value);
  }

  Uint8List encode() {
    Uint8List content = bigIntToBytes(value,
        outLen: value.isNegative ? null : ((value.bitLength + 7) >> 3) + 1);
    return ASN1Object.pack(tag, content);
  }
}

class ASN1Null implements ASN1Object {
  final int tag = ASN1Type.nullTag;

  const ASN1Null();

  factory ASN1Null.decode(Iterable<int> bytes) {
    if(bytes.length < 2) {
      throw Exception('Invalid data!');
    }

    int tag = bytes.first;
    if(tag != ASN1Type.nullTag) {
      throw Exception('Invalid tag!');
    }
    bytes = bytes.skip(1);

    if(bytes.first != 0) {
      throw Exception('Invalid length!');
    }

    return ASN1Null();
  }

  Uint8List encode() {
    final ret = Uint8List(2);
    ret[0] = tag;
    ret[1] = 0;

    return ret;
  }
}

class ASN1OctetString implements ASN1Object {
  final int tag = ASN1Type.octetStringTag;

  Uint8List value;

  ASN1OctetString(this.value);

  Uint8List encode() {
    return ASN1Object.pack(tag, value);
  }
}

class ASN1ObjectIdentifier implements ASN1Object {
  final int tag = ASN1Type.objectIdentifierTag;

  Uint32List objectIdentifier;

  ASN1ObjectIdentifier(this.objectIdentifier);

  factory ASN1ObjectIdentifier.fromList(List<int> input) {
    if (input.any((element) => element < 0)) {
      throw Exception('Negative sub-identifiers not allowed');
    }

    return ASN1ObjectIdentifier(Uint32List.fromList(input));
  }

  factory ASN1ObjectIdentifier.fromString(String input) {
    final components = input.split('.').map<int>((e) => int.parse(e)).toList();
    return ASN1ObjectIdentifier.fromList(components);
  }

  int _encodeSubIdentifier(int value, ByteData output) {
    if (value != 0) {
      int numBytes = (value.bitLength / 7).ceil();
      // TODO check length
      for (int i = numBytes - 1; i >= 0; i--) {
        output.setUint8(i, (value & 0x7F) | 0x80);
        value = value >> 7;
      }
      output.setUint8(numBytes - 1, output.getUint8(numBytes - 1) & 0x7F);

      return numBytes;
    } else {
      // TODO check length
      output.setUint8(0, 0);

      return 1;
    }
  }

  Uint8List encodeContent() {
    if (objectIdentifier.length < 2) {
      throw Exception('Object identifier sould have atleast 2 subcomponents');
    }

    if (objectIdentifier[0] >= 3) {
      throw Exception(
          'First subcomponent of Object identifier should be less that 3');
    }

    if (objectIdentifier[1] >= 40) {
      throw Exception(
          'Second subcomponent of Object identifier should be less that 40');
    }

    final first = objectIdentifier[0] * 40 + objectIdentifier[1];

    int length = objectIdentifier.skip(2).fold(
        0,
        (previousValue, element) =>
            previousValue +
            (element == 0 ? 1 : (element.bitLength / 7).ceil()));
    length += first == 0 ? 1 : (first.bitLength / 7).ceil();

    final ret = Uint8List(length);
    int offset = 0;
    offset += _encodeSubIdentifier(first, ret.buffer.asByteData(offset));

    for (int element in objectIdentifier.skip(2)) {
      offset += _encodeSubIdentifier(element, ret.buffer.asByteData(offset));
    }

    if (offset != length) {
      throw Exception('error in implementation');
    }

    return ret;
  }

  Uint8List encode() {
    final content = encodeContent();
    return ASN1Object.pack(tag, content);
  }
}

class ASN1BitString implements ASN1Object {
  final int tag = ASN1Type.bitStringTag;

  Uint8List bitString;

  int _unusedBits = 0;

  int get unusedBits => _unusedBits;

  set unusedBits(int value) {
    if (value < 0) {
      throw Exception('unused bits cannot be negative');
    } else if (value > 7) {
      throw Exception('unused bits cannot be larger than 7');
    }

    _unusedBits = value;
  }

  ASN1BitString(this.bitString, {int unusedBits = 0})
      : _unusedBits = unusedBits;

  Iterable<int> encodeContent() {
    return <int>[
      unusedBits,
      ...bitString,
    ];
  }

  Uint8List encode() {
    Iterable<int> content = encodeContent();
    return ASN1Object.pack(tag, content);
  }
}

// TODO IA5String

// TODO utf8String

// TODO set

// TODO UtcTime

// TODO enumerated
