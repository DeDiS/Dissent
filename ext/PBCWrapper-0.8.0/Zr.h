#ifndef __Zr_H__
#define __Zr_H__

#include <gmp.h>
#include "Pairing.h"

using namespace std;

class Zr {//Ring
public:
  //Create a null element
  Zr() {elementPresent = false;}
  
  //Create and initialize an element
  Zr(const Pairing &e);
  
  //Create a random element
  Zr(const Pairing &e, bool random);

  //Create an element from long int  
  Zr(const Pairing &e, long int i);

  //Create an element from GMP
  Zr(const Pairing &e, mpz_t z);

  //Create an element from import 
  //Traditional Import, bool is not imported
  Zr(const Pairing &e, const unsigned char *data, 
	 unsigned short len, unsigned short base = 16);

  //Create an element from hash
  Zr(const Pairing &e, const void *data, 
	 unsigned short len);

  //Initializes as another element, but with different value
  Zr(const Zr &s, long int i);

  //Copy constructor
  Zr(const Zr &s);

  //Destructor
  ~Zr();


  // Assignment operator 
  Zr& operator=(const Zr &rhs);  
 
  //Arithmetic Assignment Operators
  Zr& operator+=(const Zr &rhs);
  Zr& operator-=(const Zr &rhs);
  Zr& operator*=(const Zr &rhs);
  Zr& operator/=(const Zr &rhs);
  Zr& operator^=(const Zr &rhs);

  // Non-assignment operators  
  const Zr operator+(const Zr &rhs) const {
    return Zr(*this) += rhs;
  }

  const Zr operator-(const Zr &rhs) const {
    return Zr(*this) -= rhs;
  }

  const Zr operator*(const Zr &rhs) const {
    return Zr(*this) *= rhs;
  }

  const Zr operator/(const Zr &rhs) const {
    return Zr(*this) /= rhs;
  }

  const Zr operator^(const Zr &exp) const {
    return Zr(*this) ^= exp;
  }

  bool operator==(const Zr &rhs) const;
  bool isIdentity(bool additive = false) const;
  const Zr inverse(bool additive = false) const;
  const Zr square() const;

  //Assume that element_t is of the type Zr
  //For internal use only
  void setElement(const element_t& el);

  //Set an element from hash
  //void setElement(const Pairing &e, const void* data, unsigned short len);

  //Set an element from import
  //void setElement(const Pairing &e, const unsigned char *data, 
  //			    unsigned short len, unsigned short base = 16);

  //Set an element from long int
  //void setElement(const Pairing &e, long int i);

  //For internal use only
  const element_t& getElement() const;

  unsigned short getElementSize() const;

  bool isElementPresent() const {
	return elementPresent;
  }


  string toString() const;

  // Dump the element to stdout
  void dump(FILE *f, const char *label = NULL, 
			unsigned short base = 16) const;	

private:
  element_t r;
  bool elementPresent;

  void nullify();
};

#endif
