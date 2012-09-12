#ifndef __Pairing_H__
#define __Pairing_H__

#include <string>
#include <gmp.h>
extern "C" {
#include <pbc/pbc.h>
}

using namespace std;

class G1;
class G2;
class GT;

typedef enum {Type_G1, Type_G2, Type_GT, Type_Zr} PairingElementType;

class Pairing{
public:
  //Create a null pairing
  Pairing(){
	pairingPresent = false;
  }

  //Create using a buffer
  Pairing(const char * buf, size_t len);

  //Create using a ASCIIZ string
  Pairing(const char * buf);

  //Create using a File Stream
  Pairing(const FILE * buf);

  //Destructor
  ~Pairing();
	
  const pairing_t& getPairing() const;

  //Is Pairing Symmetric  
  bool isSymmetric() const;

  //Is Pairing Present
  bool isPairingPresent() const{
	return pairingPresent;
  }

  //Apply Pairing
  const GT operator()(const G1& p, const G2& q) const;
  //Symmetric Pairings
  const GT operator()(const G1& p, const G1& q) const;
  const GT operator()(const G2& p, const G2& q) const;

  //Apply Pairing
  const GT apply(const G1& p, const G2& q) const;
  //Symmetric Pairings
  const GT apply(const G1& p, const G1& q) const;
  const GT apply(const G2& p, const G2& q) const;
 

  //Element Size
  size_t getElementSize(PairingElementType type, 
						bool compressed = false) const;

  /*
  //Generate parameters for type A pairing
  static void 
  generateTypeAPairingParam(const FILE *stream, 
							unsigned short rbits =160,
							unsigned short qbits =512);

  //Generate parameters for type A1 pairing
  static void generateTypeA1PairingParam(const FILE *stream, 
										 const mpz_t n);
							 
  //Generate parameters for type D pairing
  static void 
  generateTypeDPairingParam(const FILE *stream, bool MNTorFreeman,
							unsigned int discriminant, 
							unsigned int bitlimit);

  //Generate parameters for type E pairing
  static void 
  generateTypeEPairingParam(const FILE *stream, 
							unsigned short rbits =160,
							unsigned short qbits =1024);

  //Generate parameters for type F pairing
  static void 
  generateTypeFPairingParam(const FILE *stream, 
							unsigned short bits =160);

  //Generate parameters for type G pairing
  static void 
  generateTypeGPairingParam(const FILE *stream, 
							unsigned short bits =160);  

  //Generate parameters for type G pairing
  static void 
  generateTypeGPairingParam(const FILE *stream, bool MNTorFreeman,
							unsigned int discriminant, 
							unsigned int bitlimit);

  // Dump the pairing to stdout
  //void dump(FILE *f, char *label = NULL) const;	
*/

private:
  //Copy constructor
  Pairing(const Pairing &g1);

  // Assignment operator: 
  Pairing& operator=(const Pairing &rhs);

  pairing_t e;
  bool pairingPresent;
};

#endif
