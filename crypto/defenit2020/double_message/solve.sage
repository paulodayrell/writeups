#!/usr/bin/env sage
from Crypto.Util.number import long_to_bytes

n = 0xcfb6152ae5a6f9a40e97f84e0869ac7e20f90bfa0318df1878dc69eba44df38e549cda7946dc6ceebdd8bac4c0b94053d6d7044d30ff3ce6c55faeeb120d01c77dc2f1633af9ead59f6356bba03c43252ea2fed558252dfea465b108fc3261f080f17fd3db442b3e5e6cfceb6cbcc2323683db5f862bd1df093e73b7373a77750f4a3cbf38c44559b1252981f0d9325b10d90dbdf44cc982f4c7f955025b639cf9736977d84253b3473001cc0778776ce3d8442d3f300d65efb920ca289d8321b38f2eaf0314e9c14acea509709852839a7367dba5efd03f41e595b51a69a96ee1ea7626496746a318b8583a2bbc8920c25c085f7237c248530b847f5d146fd3

c1 = 0x86a4cc0a6a8f22fe35b11870b741495a9d9abc84e1ec76e03bd3495832b260aa9014b621bf515258ba33c72f94e75df8ab3969bedc86dd946af79cb0f333ae16267d4728ad5b3e48ff72439a159b0b1d0cd5303765607fbe58353361ae7ac27eabc0bebdecc2bcaeb4a18a3463deb4527d7078d9ed9141d79e3e819e2a407ce6a71933c587e4da51a2d936c1233247246936880de615db6511b2588977b6e974ff900daa5901af0df1d4623cbdb6b5939082621397bb20b6da3f40d0020d16fa2d9a5820bf2135725d164d338684809084353efea1c8339d4367e152a54ca36e42e94f0cd67392af2fa4ade80e3ba6173b642c3a9848b65d5214ac870786aa3e

c2 = 0x79f267c0b913f21f508a65d85e43a95e28896f92d127feeabe2e5f8068f518ae2fc9315753cd3eb116a4a8410b65ebfc70ed3c183d034ff48296f919a80564e5c91fcf7c9d3ffbc101dc3d155703609d6be3546d6edabbb27201543a93172d9b24a19835c298f6cae8f0ead507971463549fc9b165000fd9ea75b5181a361769fed258091be76ffccdf347d404a95d6b7f33ee4bd2d61e7b2c935cc93394b69cf281fed2ebebb5e5174e0a3a820cdb9ed16a0bebb7dc919cba560a99d47db2d35a3cd92e3ace4cca42666c2cc3b85705796690941b3861a468ec07fb178e057ff6327b0514830d85535d5d7fb9a3d85ab46ae89842cc7e3af06d6f6a1eeef1ae

e = 3

def small_diff(padding):
  global c1, c2
  PRxy.<x,y> = PolynomialRing(Zmod(n))
  PRx.<xn> = PolynomialRing(Zmod(n))
  PRZZ.<xz,yz> = PolynomialRing(Zmod(n))

  f1 = x**e - c1
  f2 = (x + y)**e - c2

  g1 = f1.change_ring(PRZZ)
  g2 = f2.change_ring(PRZZ)

  h = g2.resultant(g1)
  h = h.univariate_polynomial()
  h = h.change_ring(PRx).subs(y=xn)
  h = h.monic()

  r = h.small_roots(X=2**padding, beta=0.3)

  if r[0] > 2**32:
    r[0] = -r[0]
    c1, c2 = c2, c1
  return r[0]

def franklin_reiter(diff):
  R.<x> = Zmod(n)[]
  f1 = R(x^e - c1)
  f2 = R((x + diff)^e - c2)

  while f2:
    f1, f2 = f2, f1 % f2
  f = f1.monic()
  return -f[0]

diff = small_diff(128)
print(long_to_bytes(franklin_reiter(diff))[:-16])

