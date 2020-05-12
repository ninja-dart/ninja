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

  Uint8List encode() {
    final ret = Uint8List(3);
    ret[0] = tag;
    ret[1] = 1;
    ret[2] = value ? 0xFF: 0x00;

    return ret;
  }
}

class ASN1Integer implements ASN1Object {
  final int tag = ASN1Type.integerTag;

  BigInt value;

  ASN1Integer(this.value);

  Uint8List encode() {
    final content = bigIntToBytes(value);

    return ASN1Object.pack(tag, content);
  }
}

class ASN1Null implements ASN1Object {
  final int tag = ASN1Type.nullTag;

  const ASN1Null();

  Uint8List encode() {
    final ret = Uint8List(2);
    ret[0] = tag;
    ret[1] = 0;

    return ret;
  }
}
