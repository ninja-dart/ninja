# Generate private key

```bash
openssl genrsa -out priv.pem 1024
```

# Extract public key

```bash
openssl rsa -in priv.pem -out pub.pem -pubout -outform PEM
```

# Dump modulus

```bash
openssl rsa -in pub.pem -pubin -modulus
openssl rsa -in priv.pem -modulus
```

## Hex to int

```bash
echo 'ibase=16;F3B24371577F76061B9F6D25720B7C21A4EEF55CE1DFDFF0D63F251F34A1B571AEC4855A9144529F14D5EE6D87AF8C0D9579708453644D6B93661CBF0F987CABDB6C1E0C3D8A274619044F51CCFB3FBA1D525FC373F596CB48EA6F8F8F56E22A3ABD3DABA79F816EFDBA2E10BFCC6F1D3797935FD16DA219791F4B5D8CD2FB2B' | bc
```

# ASN1 dump

```bash
openssl asn1parse -in priv.pem -i -dump
```