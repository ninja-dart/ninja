import 'package:asn1lib/asn1lib.dart';
import 'package:crypto/crypto.dart' as crypto;

class EmsaHasher {
  final List<int> asn1ObjectId;

  final String name;

  final crypto.Hash hasher;

  EmsaHasher(this.asn1ObjectId, this.name, this.hasher);

  List<int> hash(List<int> msg) => hasher.convert(msg).bytes;

  static final sha256 = EmsaHasher(
      [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
      'SHA-256',
      crypto.sha256);

  static final sha1 =
      EmsaHasher([0x2b, 0x0e, 0x03, 0x02, 0x1a], 'SHA-1', crypto.sha1);
}

/// Implements https://tools.ietf.org/html/rfc3447#section-9.2 specification.
List<int> emsaPkcs1V1dot5Encode(
    List<int> msg, int outLength, EmsaHasher hasher) {
  final hashed = hasher.hash(msg);

  final asn1 = ASN1Sequence()
    ..elements.addAll([
      ASN1Sequence()
        ..elements
            .addAll([ASN1ObjectIdentifier(hasher.asn1ObjectId), ASN1Null()]),
      ASN1OctetString(hashed)
    ]);
  final t = asn1.encodedBytes;

  if (outLength < t.length + 11) {
    throw Exception("intended encoded message length too short");
  }

  return <int>[
    0,
    1,
    ...List<int>.filled(outLength - t.length - 3, 255),
    0,
    ...t
  ];
}
