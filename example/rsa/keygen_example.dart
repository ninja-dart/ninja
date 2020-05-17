import 'package:ninja/asymmetric/rsa/rsa.dart';

void main() {
  final privateKey = RSAPrivateKey.generate(1024);
  print(privateKey.p);
  print(privateKey.q);
  print(privateKey.n.bitLength);
}