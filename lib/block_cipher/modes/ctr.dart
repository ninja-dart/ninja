import 'dart:collection';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:ninja/ninja.dart';

final ctrBlockCipherMode = CTRBlockCipherMode();

class CTRBlockCipherMode {
  CTRBlockCipherMode();

  Uint8List encrypt(BlockCipher cipher, /* String | Iterable<int> */ input,
      {required Uint8List iv, Padder? padder}) {
    if (input is String) {
      input = utf8.encode(input);
    }

    Uint8List padded;
    if (padder != null) {
      padded = padder.pad(cipher.blockSize, input);
    } else {
      padded = Uint8List.fromList(input);
    }

    final state = CTRState(cipher, iv);
    final out = Uint8List(padded.length);

    for (int i = 0; i < padded.length; i++) {
      final ebyte = state.nextByte;
      out[i] = padded[i] ^ ebyte;
      // Debug print('Encrypt: inp: ${padded[i]}, ebyte: ${ebyte}, out: ${out[i]}');
    }

    return out;
  }

  Uint8List decrypt(BlockCipher cipher, /* String | Uint8List */ input,
      {required Uint8List iv, Padder? padder}) {
    Uint8List inp;
    if (input is String) {
      inp = base64Decode(input);
    } else {
      inp = input;
    }

    final state = CTRState(cipher, iv);
    var out = Uint8List(inp.length);

    for (int i = 0; i < inp.length; i++) {
      final ebyte = state.nextByte;
      out[i] = inp[i] ^ ebyte;
      // Debug print('Decrypt: inp: ${inp[i]}, ebyte: ${ebyte}, out: ${out[i]}');
    }

    if (padder != null) {
      out = Uint8List.fromList(padder.unpad(cipher.blockSize, out).toList());
    }

    return out;
  }

  static Uint8List makeRandomIV({Random? random}) {
    random ??= Random.secure();
    return Uint8List.fromList(List.generate(16, (i) => random!.nextInt(256)));
  }
}

class CTRState {
  final BlockCipher cipher;

  final Uint8List _counter;

  final Queue<int> encryptedCounterBuffer;

  CTRState(this.cipher, Uint8List counter,
      {Iterable<int> encryptedCounterBuffer = const []})
      : _counter = Uint8List.fromList(counter),
        encryptedCounterBuffer = Queue.from(encryptedCounterBuffer);

  int get nextByte {
    if (encryptedCounterBuffer.isEmpty) {
      _refill();
    }
    return encryptedCounterBuffer.removeFirst();
  }

  void _refill() {
    final out = Uint8List(cipher.blockSize);
    cipher.processBlock(_counter.buffer.asByteData(), out.buffer.asByteData());
    encryptedCounterBuffer.addAll(out);
    incrementCounter(_counter);
  }

  static void incrementCounter(Uint8List counter) {
    for (int i = counter.length - 1; i >= 0; i--) {
      counter[i]++;
      if (counter[i] != 0) {
        break;
      }
    }
  }
}
