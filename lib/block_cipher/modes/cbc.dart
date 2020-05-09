import 'dart:convert';
import 'dart:typed_data';

import 'package:ninja/block_cipher/block_cipher.dart';
import 'package:ninja/ninja.dart';
import 'package:ninja/utils/listops.dart';

final cbcBlockCipherMode = CbcBlockCipherMode();

class CbcBlockCipherMode {
  CbcBlockCipherMode();

  Uint8List encrypt(BlockCipher cipher, input,
      {Iterable<int> iv, Padder padder = const PKCS7Padder()}) {
    Iterable<int> mangler;
    if (iv != null) {
      if (iv.length != cipher.blockSize) {
        throw Exception('Invalid initial vector length');
      }
      mangler = iv;
    } else {
      mangler = Uint8List(cipher.blockSize);
    }

    if (input is String) {
      input = utf8.encode(input);
    }
    final padded = padder.pad(cipher.blockSize, input);

    final numBlocks = (padded.length / cipher.blockSize).ceil();
    final out = Uint8List(numBlocks * cipher.blockSize);

    int offset = 0;
    for (int i = 0; i < numBlocks; i++) {
      final inputBlock =
          ListOps.xor(padded.skip(offset).take(cipher.blockSize), mangler)
              .buffer
              .asByteData();
      final outputBlock = out.buffer.asByteData(offset, cipher.blockSize);
      cipher.processBlock(inputBlock, outputBlock);
      mangler = out.skip(offset).take(cipher.blockSize);
      offset += cipher.blockSize;
    }

    return out;
  }

  Iterable<int> decrypt(BlockCipher cipher, /* String | Uint8List */ input,
      {Iterable<int> iv, Padder padder = const PKCS7Padder()}) {
    Iterable<int> mangler;
    if (iv != null) {
      if (iv.length != cipher.blockSize) {
        throw Exception('Invalid initial vector length');
      }
      mangler = iv;
    } else {
      mangler = Uint8List(cipher.blockSize);
    }

    if(input is String) {
      input = base64Decode(input);
    }

    final numBlocks = (input.length / cipher.blockSize).ceil();
    final decrypted = Uint8List(numBlocks * cipher.blockSize);

    int offset = 0;
    for (int i = 0; i < numBlocks; i++) {
      final inputBlock = input.buffer.asByteData(offset, cipher.blockSize);
      final outputBlock = decrypted.buffer.asByteData(offset, cipher.blockSize);
      cipher.processBlock(inputBlock, outputBlock);
      ListOps.xorToByteData(outputBlock, mangler);
      mangler = input.skip(offset).take(cipher.blockSize);
      offset += cipher.blockSize;
    }

    final unpadded = padder.unpad(cipher.blockSize, decrypted).toList();
    
    return unpadded;
  }
}
