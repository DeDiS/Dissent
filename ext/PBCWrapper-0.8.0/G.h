#ifndef __G_H__
#define __G_H__

#include "Pairing.h"
#include "Zr.h"

using namespace std;

class G {//Group
public:

  //Destructor
  ~G();

  bool isIdentity() const;
  void setElement(const element_t& el);

  //Create an element from hash
  //Assumes that g is already initialized
  //void setElement(const void* data,  unsigned short len);

  //Create an element from import
  //Assumes that g is already initialized and for element of type GT
  //bool compressed is not set to true
  //void setElement(const unsigned char *data, unsigned short len, 
  //				  bool compressed = false, unsigned short base = 16);

  const element_t& getElement() const;
  unsigned short getElementSize() const;
  bool isElementPresent() const{return elementPresent;}

  string toString() const;

  // Dump the element to a buffer (calls element_snprintf)
  int dump(char *buf, int buflen) const;
  
  // Dump the element to stdout (print friendly)
  void dump(FILE *f, const char *label = NULL,
			unsigned short base = 16) const;	

protected:	
  element_t g;
  bool elementPresent;

  //Intialize with another element and assign identity or same element
  G(const G &h, bool identity=false);

  //Copy constructor
  //G(const G &h);

  //Create a null element
  G() {elementPresent = false;}

  //Create and initialize an element
  G(const Pairing &e){ 
	elementPresent = e.isPairingPresent();
  }

  // Assignment operator 
  G& operator=(const G &rhs);  

  //Arithmetic Assignment Operators
  G& operator*=(const G &rhs);
  G& operator/=(const G &rhs);
  G& operator^=(const Zr &exp);

  bool operator==(const G &rhs) const;
  const G inverse() const;
  const G square() const;

private:
  void nullify();
};
#endif
