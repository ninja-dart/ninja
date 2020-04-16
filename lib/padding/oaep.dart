import 'dart:math';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:ninja/ninja.dart';

class OAEPPadder implements Padder {
  final Digest hasher;

  final Random random;

  OAEPPadder({Digest hasher, this.random}): hasher = hasher ?? sha1;

  Uint8List pad(Uint8List data) {
    // TODO
  }

  Uint8List unpad(Uint8List data) {
    // TODO
  }
}