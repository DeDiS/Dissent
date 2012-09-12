#ifndef __G1_H__
#define __G1_H__

#include "G.h"
using namespace std;

class G1: public G {
public:
  G1(){};

 //Create and initialize an element
  G1(const Pairing &e);

  //Create an identity or a random element
  G1(const Pairing &e, bool identity);

  //Create an element from import 
  G1(const Pairing &e, const unsigned char *data, unsigned short len, 
	 bool compressed, unsigned short base);

  //Create an element from hash
  G1(const Pairing &e, const void *data, unsigned short len);

  //Intialize with another element but with different value
  G1(const G1 &h, bool identity=false):G(h,identity){}

  //Copy constructor
  //G1(const G1 &h):G(h){}

  // Assignment operator 
  G1& operator=(const G1 &rhs){return (G1&)G::operator=(rhs);}

  //Arithmetic Assignment Operators
  G1& operator*=(const G1 &rhs){return (G1&)G::operator*=(rhs);}
  G1& operator/=(const G1 &rhs){return (G1&)G::operator/=(rhs);}
  G1& operator^=(const Zr &exp){return (G1&)G::operator^=(exp);}

  // Non-assignment operators
  const G1 operator*(const G1 &rhs) const {
    return G1(*this) *= rhs;
  }
  const G1 operator/(const G1 &rhs) const {
    return G1(*this) /= rhs;
  }

  const G1 operator^(const Zr &exp) const {
    return G1(*this) ^= exp;
  }

  bool operator==(const G1 &rhs) const {
	return G::operator==(rhs);
  }

  unsigned short getElementSize(bool compressed) const;

  string toString(bool compressed) const;

  const G1 inverse() const{
	G1 g1;
	g1.setElement(G::inverse().getElement());
	return g1;
  }
  const G1 square() const{
	G1 g1;
	g1.setElement(G::square().getElement());
	return g1;
  }
};

#endif
