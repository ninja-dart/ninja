import 'dart:convert';
import 'dart:typed_data';

class HexStringDecoder extends Converter<String, Uint8List> {
  const HexStringDecoder();

  @override
  Uint8List convert(String input) {
    final result = Uint8List(input.length ~/ 2);
    for (int i = 0; i < input.length; i += 2) {
      var num = input.substring(i, i + 2);
      var byte = int.parse(num, radix: 16);
      result[i ~/ 2] = byte;
    }
    return result;
  }
}

class HexStringEncoder extends Converter<Iterable<int>, String> {
  const HexStringEncoder();

  @override
  String convert(Iterable<int> input) {
    final result = StringBuffer();
    for (int part in input) {
      result.write('${part < 16 ? '0' : ''}${part.toRadixString(16)}');
    }
    return result.toString();
  }
}

class HexCodec extends Codec<Iterable<int>, String> {
  const HexCodec();

  @override
  Converter<Iterable<int>, String> get encoder => hexEncoder;

  @override
  Converter<String, Uint8List> get decoder => hexDecoder;
}

const hexDecoder = HexStringDecoder();

const hexEncoder = HexStringEncoder();

const hexCodec = HexCodec();

Uint8List hexDecode(String input) => hexDecoder.convert(input);

String hexEncode(Iterable<int> input) => hexEncoder.convert(input);
