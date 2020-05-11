/// https://tools.ietf.org/html/rfc7468
class PemPart {
  final String label;

  final String data;

  PemPart(this.label, this.data);

  factory PemPart.decodeFirst(String pem) {
    final lines = pem.split(_newlineRegexp).reversed.toList();

    final part = _decodeNextPem(lines);
    if (part != null) return part;

    throw Exception('No block found');
  }

  factory PemPart.decodeLabelled(String pem, String label) {
    final lines = pem.split(_newlineRegexp).reversed.toList();

    while(true) {
      final part = _decodeNextPem(lines);
      if(part == null) break;

      if(part.label == label) return part;
    }

    throw Exception('No block found');
  }

  String toString({String eol = '\n'}) {
    final sb = StringBuffer();

    // preeb
    sb.write(_begin);
    sb.write(label);
    sb.write(_suffix);
    sb.write(eol);

    // data
    Iterable<int> bytes = data.runes;
    while (bytes.isNotEmpty) {
      Iterable<int> block;
      if (bytes.length > 64) {
        block = bytes.take(64);
        bytes = bytes.skip(64);
      } else {
        block = bytes;
        bytes = <int>[];
      }

      sb.write(String.fromCharCodes(block));
      sb.write(eol);
    }

    // posteb
    sb.write(_end);
    sb.write(label);
    sb.write(_suffix);

    return sb.toString();
  }

  bool operator==(other) {
    if(other is PemPart) {
      return label == other.label && data == other.data;
    }

    return false;
  }

  static String encode(Iterable<PemPart> parts, {String eol = '\n'}) =>
      parts.map((part) => part.toString(eol: eol)).join(eol);

  static List<PemPart> decodeAll(String input) {
    final lines = input.split(_newlineRegexp).reversed.toList();

    final ret = <PemPart>[];

    PemPart part;
    while (true) {
      part = _decodeNextPem(lines);
      if (part == null) break;

      ret.add(part);
    }

    return ret;
  }

  static const _begin = "-----BEGIN ";

  static const _end = "-----END ";

  static const _suffix = "-----";

  static final _newlineRegexp = RegExp(r'\n|\r|(\r\n)');

  static final _base64Regexp = RegExp('[a-zA-Z0-9+/=]');
}

PemPart _decodeNextPem(List<String> input) {
  String label;

  // preeb
  while (input.isNotEmpty) {
    String line = input.removeLast();
    if (!line.startsWith(PemPart._begin)) {
      continue;
    }
    line = line.substring(11);

    int index = line.indexOf(PemPart._suffix);
    if (index == null) {
      throw Exception('Invalid BEGIN line');
    }

    label = line.substring(0, index);

    line = line.substring(index + 5);

    if (line.runes.any(_isNotWhitespace)) {
      throw Exception('Invalid BEGIN line');
    }

    break;
  }

  if(label == null) return null;

  while(input.isNotEmpty && _isEmptyLine(input.last)) {
    input.removeLast();
  }

  if(input.isEmpty) {
    throw Exception('Unexpected end of text');
  }

  final sb = StringBuffer();
  while(input.isNotEmpty && !_isEndOfBlock(input.last)) {
    String line = input.removeLast();
    int index = line.lastIndexOf(PemPart._base64Regexp);
    if(index == null) {
      throw Exception('Invalid data line');
    }
    if(index > 64) {
      throw Exception('Data line too long');
    }

    if(line.substring(index + 1).runes.any(_isNotWhitespace)) {
      throw Exception('Invalid data line');
    }

    String data = line.substring(0, index + 1);
    sb.write(data);
  }

  if(input.isEmpty) {
    throw Exception('Unexpected end of text');
  }

  input.removeLast();

  return PemPart(label, sb.toString());
}

bool _isEmptyLine(String input) {
  if(input.isEmpty) return true;

  if(input.runes.any(_isNotWhitespace)) {
    return false;
  }

  return true;
}

bool _isEndOfBlock(String line) {
  if (!line.startsWith(PemPart._end)) {
    return false;
  }
  line = line.substring(9);

  int index = line.indexOf(PemPart._suffix);
  if (index == null) {
    throw Exception('Invalid END line');
  }

  String label = line.substring(0, index);
  // TODO check if label is valid

  line = line.substring(index + 5);

  if (line.runes.any(_isNotWhitespace)) {
    throw Exception('Invalid END line');
  }

  return true;
}

bool _isWhitespace(int rune) => rune == 0x20 || rune == 0x09;
bool _isNotWhitespace(int rune) => rune != 0x20 && rune != 0x09;
