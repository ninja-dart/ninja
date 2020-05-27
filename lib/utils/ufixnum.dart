// This file has been copied and modified from pointy_castles package. See file
// LICENSE/pointy_castle_LICENSE file for more information.

library ninja.ufixnum;

const _MASK_3 = 0x07;
const _MASK_5 = 0x1F;
const _MASK_6 = 0x3F;
const _MASK_8 = 0xFF;
const _MASK_16 = 0xFFFF;
const _MASK_32 = 0xFFFFFFFF;

final _MASK32_HI_BITS = [
  0xFFFFFFFF,
  0x7FFFFFFF,
  0x3FFFFFFF,
  0x1FFFFFFF,
  0x0FFFFFFF,
  0x07FFFFFF,
  0x03FFFFFF,
  0x01FFFFFF,
  0x00FFFFFF,
  0x007FFFFF,
  0x003FFFFF,
  0x001FFFFF,
  0x000FFFFF,
  0x0007FFFF,
  0x0003FFFF,
  0x0001FFFF,
  0x0000FFFF,
  0x00007FFF,
  0x00003FFF,
  0x00001FFF,
  0x00000FFF,
  0x000007FF,
  0x000003FF,
  0x000001FF,
  0x000000FF,
  0x0000007F,
  0x0000003F,
  0x0000001F,
  0x0000000F,
  0x00000007,
  0x00000003,
  0x00000001,
  0x00000000
];

////////////////////////////////////////////////////////////////////////////////////////////////////
// 8 bit operations
//
int clip8(int x) => (x & _MASK_8);

int csum8(int x, int y) => sum8(clip8(x), clip8(y));
int sum8(int x, int y) {
  assert((x >= 0) && (x <= _MASK_8));
  assert((y >= 0) && (y <= _MASK_8));
  return ((x + y) & _MASK_8);
}

int csub8(int x, int y) => sub8(clip8(x), clip8(y));
int sub8(int x, int y) {
  assert((x >= 0) && (x <= _MASK_8));
  assert((y >= 0) && (y <= _MASK_8));
  return ((x - y) & _MASK_8);
}

int cshiftl8(int x, int n) => shiftl8(clip8(x), n);
int shiftl8(int x, int n) {
  assert((x >= 0) && (x <= _MASK_8));
  return ((x << (n & _MASK_3)) & _MASK_8);
}

int cshiftr8(int x, int n) => shiftr8(clip8(x), n);
int shiftr8(int x, int n) {
  assert((x >= 0) && (x <= _MASK_8));
  return (x >> (n & _MASK_3));
}

int cneg8(int x) => neg8(clip8(x));
int neg8(int x) {
  assert((x >= 0) && (x <= _MASK_8));
  return (-x & _MASK_8);
}

int cnot8(int x) => not8(clip8(x));
int not8(int x) {
  assert((x >= 0) && (x <= _MASK_8));
  return (~x & _MASK_8);
}

int crotl8(int x, int n) => rotl8(clip8(x), n);
int rotl8(int x, int n) {
  assert(n >= 0);
  assert((x >= 0) && (x <= _MASK_8));
  n &= _MASK_3;
  return ((x << n) & _MASK_8) | (x >> (8 - n));
}

int crotr8(int x, int n) => rotr8(clip8(x), n);
int rotr8(int x, int n) {
  assert(n >= 0);
  assert((x >= 0) && (x <= _MASK_8));
  n &= _MASK_3;
  return ((x >> n) & _MASK_8) | ((x << (8 - n)) & _MASK_8);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// 16 bit operations
//
int clip16(int x) => (x & _MASK_16);

////////////////////////////////////////////////////////////////////////////////////////////////////
// 32 bit operations
//
int clip32(int x) => (x & _MASK_32);

int csum32(int x, int y) => sum32(clip32(x), clip32(y));
int sum32(int x, int y) {
  assert((x >= 0) && (x <= _MASK_32));
  assert((y >= 0) && (y <= _MASK_32));
  return ((x + y) & _MASK_32);
}

int csub32(int x, int y) => sub32(clip32(x), clip32(y));
int sub32(int x, int y) {
  assert((x >= 0) && (x <= _MASK_32));
  assert((y >= 0) && (y <= _MASK_32));
  return ((x - y) & _MASK_32);
}

int cshiftl32(int x, int n) => shiftl32(clip32(x), n);
int shiftl32(int x, int n) {
  assert((x >= 0) && (x <= _MASK_32));
  n &= _MASK_5;
  x &= _MASK32_HI_BITS[n];
  return ((x << n) & _MASK_32);
}

int cshiftr32(int x, int n) => shiftr32(clip32(x), n);
int shiftr32(int x, int n) {
  assert((x >= 0) && (x <= _MASK_32));
  n &= _MASK_5;
  return (x >> n);
}

int cneg32(int x) => neg32(clip32(x));
int neg32(int x) {
  assert((x >= 0) && (x <= _MASK_32));
  return (-x & _MASK_32);
}

int cnot32(int x) => not32(clip32(x));
int not32(int x) {
  assert((x >= 0) && (x <= _MASK_32));
  return (~x & _MASK_32);
}

int crotl32(int x, int n) => rotl32(clip32(x), n);
int rotl32(int x, int n) {
  assert(n >= 0);
  assert((x >= 0) && (x <= _MASK_32));
  n &= _MASK_5;
  return shiftl32(x, n) | (x >> (32 - n));
}

int crotr32(int x, int n) => rotr32(clip32(x), n);
int rotr32(int x, int n) {
  assert(n >= 0);
  assert((x >= 0) && (x <= _MASK_32));
  n &= _MASK_5;
  return (x >> n) | shiftl32(x, (32 - n));
}
