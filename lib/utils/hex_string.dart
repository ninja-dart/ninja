import 'dart:convert';
import 'dart:typed_data';

class HexStringEncoder extends Converter<String, Uint8List> {
  const HexStringEncoder();

  @override
  Uint8List convert(String input) {
    var result = new Uint8List(input.length ~/ 2);
    for (var i = 0; i < input.length; i += 2) {
      var num = input.substring(i, i + 2);
      var byte = int.parse(num, radix: 16);
      result[i ~/ 2] = byte;
    }
    return result;
  }
}

class HexStringDecoder extends Converter<Uint8List, String> {
  const HexStringDecoder();

  @override
  String convert(Uint8List input) {
    var result = StringBuffer();
    for (var i = 0; i < input.lengthInBytes; i++) {
      int part = input[i];
      result.write('${part < 16 ? '0' : ''}${part.toRadixString(16)}');
    }
    return result.toString();
  }
}

class HexString extends Codec<String, Uint8List> {
  const HexString();

  @override
  Converter<String, Uint8List> get encoder => hexStringEncoder;

  @override
  Converter<Uint8List, String> get decoder => hexStringDecoder;
}

const hexStringEncoder = HexStringEncoder();

const hexStringDecoder = HexStringDecoder();

const hexString = HexString();