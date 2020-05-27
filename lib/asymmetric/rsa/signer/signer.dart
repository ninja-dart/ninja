import 'package:ninja/asymmetric/rsa/rsa.dart';

export 'emsa_pss.dart';
export 'rsassa_pks1_v15.dart';

abstract class RsaSigner {
  List<int> sign(RSAPrivateKey key, /* String | List<int> | BigInt */ msg);

  String signToBase64(RSAPrivateKey key, /* String | List<int> | BigInt */ msg);
}

abstract class RsaVerifier {
  bool verify(
      RSAPublicKey key,
      /* String | List<int> | BigInt */ signature,
      /* String | List<int> | BigInt */ msg);
}
