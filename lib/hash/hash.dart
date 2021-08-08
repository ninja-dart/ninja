export 'ripemd160.dart';

import 'package:crypto/crypto.dart';
import 'package:ninja/ninja.dart';

extension DigestExt on Digest {
  String get asHex => bigIntToHex(asBigInt);

  BigInt get asBigInt => bytes.asBigInt;
}