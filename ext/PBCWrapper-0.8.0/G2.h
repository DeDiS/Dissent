#ifndef __G2_H__
#define __G2_H__

#include "G.h"
using namespace std;

class G2: public G {
public:
  G2(){};

 //Create and initialize an element
  G2(const Pairing &e);

  //Create an identity or a random element
  G2(const Pairing &e, bool identity);

  //Create an element from import 
  G2(const Pairing &e, const unsigned char *data, 
	 unsigned short len, bool compressed = false, 
	 unsigned short base = 16);

  //Create an element from hash
  G2(const Pairing &e, const void *data, 
	 unsigned short len);

  //Intialize with another element but with different value
  G2(const G2 &h, bool identity=false):G(h,identity){}

  //Copy constructor
  //G2(const G2 &h):G(h){}

  // Assignment operator 
  G2& operator=(const G2 &rhs){return (G2&)G::operator=(rhs);}

  //Arithmetic Assignment Operators
  G2& operator*=(const G2 &rhs){return (G2&)G::operator*=(rhs);}
  G2& operator/=(const G2 &rhs){return (G2&)G::operator/=(rhs);}
  G2& operator^=(const Zr &exp){return (G2&)G::operator^=(exp);}

  // Non-assignment operators
  const G2 operator*(const G2 &rhs) const {
    return G2(*this) *= rhs;
  }
  const G2 operator/(const G2 &rhs) const {
    return G2(*this) /= rhs;
  }

  const G2 operator^(const Zr &exp) const {
    return G2(*this) ^= exp;
  }

  bool operator==(const G2 &rhs) const {
	return G::operator==(rhs);
  }

  unsigned short getElementSize(bool compressed) const;

  string toString(bool compressed) const;

  const G2 inverse() const{
	G2 g2;
	g2.setElement(G::inverse().getElement());
	return g2;
  }
  const G2 square() const{
	G2 g2;
	g2.setElement(G::square().getElement());
	return g2;
  }
};

#endif
