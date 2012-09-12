
#include <iostream>
#include <stdio.h>
#include <stdlib.h>

#include <QByteArray>
#include <QTextStream>

#include <cryptopp/nbtheory.h>
#include <cryptopp/osrng.h>

QByteArray PrintInteger(const CryptoPP::Integer &i) 
{
  const int len = i.MinEncodedSize();
  char *bytes = (char*)malloc(sizeof(char) * len);
  if(!bytes) exit(1); 
  
  i.Encode((byte*)bytes, len);
  QByteArray b(bytes, len);

  return b;
}

int main(int argc, char* argv[]) {
  QTextStream err(stderr, QIODevice::WriteOnly);
  if(argc != 2) {
    err << "Usage: " << argv[0] << " pbits\n";
    return 1;
  }

  int pbits;
  QTextStream in(argv[1], QIODevice::ReadOnly);
  in >> pbits;

  if(pbits < 10) {
    err << "pbits must be greater than 10\n";
    return 1;
  }

  QTextStream out(stdout, QIODevice::WriteOnly);
  out << "--- Prime Number Utility ---\n";
  out << "p = 2q+1 (for prime p and q)\n";
  out << "g generates the group of quadratic residues mod p\n";
  out << "Bits: " << pbits << "\n";
  out << "\n\n";

  CryptoPP::AutoSeededX917RNG<CryptoPP::AES> rng(false, true);
  CryptoPP::PrimeAndGenerator pand(1, rng, pbits);

  QByteArray p, q, g;

  out << "==> p\n";
  out << PrintInteger(pand.Prime()).toHex() << "\n\n";
  out << "==> q\n";
  out << PrintInteger(pand.SubPrime()).toHex() << "\n\n";
  out << "==> g\n";
  out << PrintInteger(pand.Generator()).toHex() << "\n\n";

  return 0;
}

