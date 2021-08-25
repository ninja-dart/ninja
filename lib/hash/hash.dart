export 'ripemd160.dart';

import 'package:crypto/crypto.dart';
import 'package:ninja/ninja.dart';

extension DigestExt on Digest {
  String get asHex => bigIntToHex(asBigInt);

  BigInt get asBigInt => bytes.asBigInt();
}

/// A sink used to get a digest value out of `Hash.startChunkedConversion`.
class DigestSink extends Sink<Digest> {
  /// The value added to the sink.
  ///
  /// A value must have been added using [add] before reading the `value`.
  Digest get value => _value!;

  Digest? _value;

  /// Adds [value] to the sink.
  ///
  /// Unlike most sinks, this may only be called once.
  @override
  void add(Digest value) {
    if (_value != null) throw StateError('add may only be called once.');
    _value = value;
  }

  @override
  void close() {
    if (_value == null) throw StateError('add must be called once.');
  }
}
