// This file has been copied and modified from pointy_castles package. See file
// LICENSE/pointy_castle_LICENSE file for more information.

library ninja.ufixnum;

const mask3 = 0x07;
const mask5 = 0x1F;
const mask6 = 0x3F;
const mask8 = 0xFF;
const mask16 = 0xFFFF;
const mask32 = 0xFFFFFFFF;

final maskHiBits = [
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
int clip8(int x) => (x & mask8);

int csum8(int x, int y) => sum8(clip8(x), clip8(y));
int sum8(int x, int y) {
  assert((x >= 0) && (x <= mask8));
  assert((y >= 0) && (y <= mask8));
  return ((x + y) & mask8);
}

int csub8(int x, int y) => sub8(clip8(x), clip8(y));
int sub8(int x, int y) {
  assert((x >= 0) && (x <= mask8));
  assert((y >= 0) && (y <= mask8));
  return ((x - y) & mask8);
}

int cshiftl8(int x, int n) => shiftl8(clip8(x), n);
int shiftl8(int x, int n) {
  assert((x >= 0) && (x <= mask8));
  return ((x << (n & mask3)) & mask8);
}

int cshiftr8(int x, int n) => shiftr8(clip8(x), n);
int shiftr8(int x, int n) {
  assert((x >= 0) && (x <= mask8));
  return (x >> (n & mask3));
}

int cneg8(int x) => neg8(clip8(x));
int neg8(int x) {
  assert((x >= 0) && (x <= mask8));
  return (-x & mask8);
}

int cnot8(int x) => not8(clip8(x));
int not8(int x) {
  assert((x >= 0) && (x <= mask8));
  return (~x & mask8);
}

int crotl8(int x, int n) => rotl8(clip8(x), n);
int rotl8(int x, int n) {
  assert(n >= 0);
  assert((x >= 0) && (x <= mask8));
  n &= mask3;
  return ((x << n) & mask8) | (x >> (8 - n));
}

int crotr8(int x, int n) => rotr8(clip8(x), n);
int rotr8(int x, int n) {
  assert(n >= 0);
  assert((x >= 0) && (x <= mask8));
  n &= mask3;
  return ((x >> n) & mask8) | ((x << (8 - n)) & mask8);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// 16 bit operations
//
int clip16(int x) => (x & mask16);

////////////////////////////////////////////////////////////////////////////////////////////////////
// 32 bit operations
//
int clip32(int x) => (x & mask32);

int csum32(int x, int y) => sum32(clip32(x), clip32(y));
int sum32(int x, int y) {
  assert((x >= 0) && (x <= mask32));
  assert((y >= 0) && (y <= mask32));
  return ((x + y) & mask32);
}

int csub32(int x, int y) => sub32(clip32(x), clip32(y));
int sub32(int x, int y) {
  assert((x >= 0) && (x <= mask32));
  assert((y >= 0) && (y <= mask32));
  return ((x - y) & mask32);
}

int cshiftl32(int x, int n) => shiftl32(clip32(x), n);
int shiftl32(int x, int n) {
  assert((x >= 0) && (x <= mask32));
  n &= mask5;
  x &= maskHiBits[n];
  return ((x << n) & mask32);
}

int cshiftr32(int x, int n) => shiftr32(clip32(x), n);
int shiftr32(int x, int n) {
  assert((x >= 0) && (x <= mask32));
  n &= mask5;
  return (x >> n);
}

int cneg32(int x) => neg32(clip32(x));
int neg32(int x) {
  assert((x >= 0) && (x <= mask32));
  return (-x & mask32);
}

int cnot32(int x) => not32(clip32(x));
int not32(int x) {
  assert((x >= 0) && (x <= mask32));
  return (~x & mask32);
}

int crotl32(int x, int n) => rotl32(clip32(x), n);
int rotl32(int x, int n) {
  assert(n >= 0);
  assert((x >= 0) && (x <= mask32));
  n &= mask5;
  return shiftl32(x, n) | (x >> (32 - n));
}

int crotr32(int x, int n) => rotr32(clip32(x), n);
int rotr32(int x, int n) {
  assert(n >= 0);
  assert((x >= 0) && (x <= mask32));
  n &= mask5;
  return (x >> n) | shiftl32(x, (32 - n));
}
