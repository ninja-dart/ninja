import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:ninja/padder/mgf/mgf.dart';
import 'package:ninja/utils/listops.dart';

class EmsaPssEncoder {
  final Mgf mgf;

  final Hash hasher;

  final int saltLength;

  EmsaPssEncoder({Mgf mgf, Hash hasher, this.saltLength = 0})
      : mgf = mgf ?? mgf1Sha1,
        hasher = hasher ?? sha1;

  Uint8List encode(int blockSize, List<int> input) {
    final mHash = hasher.convert(input).bytes;

    if (blockSize < mHash.length + saltLength + 2) {
      throw Exception('encoding error. blockSize too small');
    }

    Random random = Random.secure();

    final salt = List<int>.generate(saltLength, (index) => random.nextInt(256));

    final mDash = <int>[
      ...List<int>.filled(8, 0),
      ...mHash,
      ...salt,
    ];

    final h = hasher.convert(mDash).bytes;

    final ps = List.filled(blockSize - saltLength - mHash.length - 2, 0);

    final db = <int>[
      ...ps,
      0x01,
      ...salt,
    ];

    final dbMask = mgf.encode(blockSize - mHash.length - 1, h);

    final maskedDb = ListOps.xor(db, dbMask);

    final em = Uint8List.fromList(<int>[
      ...maskedDb,
      ...h,
      0xbc,
    ]);

    return em;
  }
}
