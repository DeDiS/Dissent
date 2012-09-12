#include "Pairing.h"
#include "G1.h"
#include "G2.h"
#include "GT.h"
#include "PBCExceptions.h"

//Create using a buffer
Pairing::Pairing(const char * buf, size_t len){
  //pairing_init_inp_buf(e, buf, len);
  //pairingPresent = true;
  if (pairing_init_set_buf(e, buf, len))
	  pairingPresent = false;
	else
	  pairingPresent = true;
}

//Create using a ASCIIZ string
Pairing::Pairing(const char * buf){
  //pairing_init_inp_str(e,*(FILE**) &stream);
  //pairingPresent = true;
  if (pairing_init_set_str(e, buf))
	  pairingPresent = false;
	else
	  pairingPresent = true;
}

//Create using a File Stream
Pairing::Pairing(const FILE * buf){
  char s[8192];
  size_t count = fread(s, 1, 8192, *(FILE **) &buf);
  pairingPresent = false;	  
  if (count) 
	if (!pairing_init_set_buf(e, s, count)) 
	  pairingPresent = true;
}

//Destructor
Pairing::~Pairing(){
  if (pairingPresent){
	pairing_clear(e);
	pairingPresent = false;
  }
}

const pairing_t&  Pairing::getPairing() const{
  if (pairingPresent)
	return e;
  else
	throw UndefinedPairingException();
}

//Is Pairing Symmetric  
bool Pairing::isSymmetric() const{
  if (pairingPresent)
	return pairing_is_symmetric(*(pairing_t*)&e);
  else
	throw UndefinedPairingException();
}

//Apply Pairing
const GT Pairing::operator()(const G1& p, const G2& q) const{
  if(pairingPresent)
	if (p.isElementPresent()&&q.isElementPresent()){
	  element_t gt;
	  element_init_GT(gt,*(pairing_t*)&e);
	  pairing_apply(gt, *(element_t*)&p.getElement(),
					*(element_t*)&q.getElement(), 
					*(pairing_t*)&e);
	  GT ans;
	  ans.setElement(gt);
	  element_clear(gt);
	  return ans;
	}else throw UndefinedElementException();
  else throw UndefinedPairingException();
}

//Symmetric Pairings
const GT Pairing::operator()(const G1& p,
							 const G1& q) const{
  if(pairingPresent)
	if (p.isElementPresent()&&q.isElementPresent())
	  if(isSymmetric()){
		element_t gt;
		element_init_GT(gt,*(pairing_t*)&e);
		pairing_apply(gt, *(element_t*)&p.getElement(),
					  *(element_t*)&q.getElement(), 
					  *(pairing_t*)&e);
		GT ans;
		ans.setElement(gt);
		element_clear(gt);
		return ans;
	  }else throw NonsymmetricPairingException();
	else throw UndefinedElementException();
  else throw UndefinedPairingException();
}

const GT Pairing::operator()(const G2& p, 
							 const G2& q) const{
  if(pairingPresent)
	if (p.isElementPresent()&&q.isElementPresent())
	  if(isSymmetric()){
		element_t gt;
		element_init_GT(gt,*(pairing_t*)&e);
		pairing_apply(gt, *(element_t*)&p.getElement(),
					  *(element_t*)&q.getElement(), 
					  *(pairing_t*)&e);
		GT ans;
		ans.setElement(gt);
		element_clear(gt);
		return ans;
	  }else throw NonsymmetricPairingException();
	else throw UndefinedElementException();
  else throw UndefinedPairingException();
}

//Apply Pairing
const GT Pairing::apply(const G1& p, const G2& q) const{	
  return (*this)(p,q);
}
  //Symmetric Pairings
const GT Pairing::apply(const G1& p, const G1& q) const{
  return (*this)(p,q);
}
const GT Pairing::apply(const G2& p, const G2& q) const{	
  return (*this)(p,q);
}

//Generate element size
size_t Pairing::getElementSize(PairingElementType type, 
									   bool compressed) const{
  if(pairingPresent){
	switch(type){
	case Type_G1:
	  if(compressed)
		return pairing_length_in_bytes_compressed_G1(*(pairing_t*)&e);
	  else
		return pairing_length_in_bytes_G1(*(pairing_t*)&e);
	case Type_G2:
	  if(compressed)
		return pairing_length_in_bytes_compressed_G2(*(pairing_t*)&e);
	  else
		return pairing_length_in_bytes_G2(*(pairing_t*)&e);
	case Type_GT:
	  return pairing_length_in_bytes_GT(*(pairing_t*)&e);
	case Type_Zr:
	  return pairing_length_in_bytes_Zr(*(pairing_t*)&e);
	default: return 0;
	}	
  }else throw UndefinedPairingException();
}

/*
//Generate parameters for type A pairing
void Pairing::
generateTypeAPairingParam(const FILE *stream, 
						  unsigned short rbits,unsigned short qbits){
  pbc_param_t p;
  //a_param_init(p);
  pbc_param_init_a_gen(p,rbits,qbits);
  pbc_param_out_str(*(FILE**)&stream, p);
  pbc_param_clear(p);
}

//Generate parameters for type A1 pairing
//n is a product of two primes (each 512 bits long at least)
void Pairing::
generateTypeA1PairingParam(const FILE *stream, const mpz_t n){
  pbc_param_t p;
  //a1_param_init(p);
  pbc_param_init_a1_gen(p,*(mpz_t*)&n);
  pbc_param_out_str(*(FILE**)&stream, p);
  pbc_param_clear(p);
}  

//Generate parameters for type D pairing
#include <cstdlib>//To generate a random number
void Pairing::
generateTypeDPairingParam(const FILE *stream, bool MNTorFreeman,
						  unsigned int discriminant, 
						  unsigned int bitlimit){
  d_param_t p;
  cm_info_t cm;
  darray_t L;
  size_t darraySize;
  unsigned int randomIndex;

  if(MNTorFreeman)//Using MNT6
	darraySize = find_mnt6_curve(L, discriminant, bitlimit);
  else	//Using Freeman
	darraySize = find_freeman_curve(L, discriminant, bitlimit);

  if(darraySize < 1){
	fprintf(*(FILE**)&stream,"No available values for given input params");
	return;
  }
  randomIndex = (unsigned int) (double(rand())/RAND_MAX)*darraySize;
  cm_info_init(cm);
  cm = L[randomIndex];

  d_param_init(p);
  d_param_from_cm(p,cm);
  d_param_out_str(*(FILE**)&stream, p);
  d_param_clear(p);
  cm_info_clear(cm);
  for(unsigned int i=0; i<darraySize; ++i)
	cm_info_clear(L[randomIndex]);
  darray_clear(L);
}

//Generate parameters for type E pairing
void Pairing::
generateTypeEPairingParam(const FILE *stream, 
						  unsigned short rbits,unsigned short qbits){
  pbc_param_t p;
  //e_param_init(p);
  pbc_param_init_e_gen(p,rbits,qbits);
  pbc_param_out_str(*(FILE**)&stream, p);
  pbc_param_clear(p);
}

//Generate parameters for type F pairing
void Pairing::
generateTypeFPairingParam(const FILE *stream, 
						  unsigned short bits){
  pbc_param_t p;
  //f_param_init(p);
  pbc_param_init_f_gen(p,bits);
  pbc_param_out_str(*(FILE**)&stream, p);
  pbc_param_clear(p);
}

//Generate parameters for type G pairing
//#include <cstdlib>//To generate a random number
void Pairing::
generateTypeGPairingParam(const FILE *stream, bool MNTorFreeman,
						  unsigned int discriminant, unsigned int bitlimit){
  g_param_t p;
  cm_info_t cm;
  darray_t L;
  size_t darraySize;
  unsigned int randomIndex;

  if(MNTorFreeman)//Using MNT6
	darraySize = find_mnt6_curve(L, discriminant, bitlimit);
  else	//Using Freeman
	darraySize = find_freeman_curve(L, discriminant, bitlimit);

  if(darraySize < 1){
	fprintf(*(FILE**)&stream,"No available values for given input params");
	return;
  }
  randomIndex = (unsigned int) (double(rand())/RAND_MAX)*darraySize;
  cm_info_init(cm);
  cm = L[randomIndex];

  g_param_init(p);
  g_param_from_cm(p,cm);
  g_param_out_str(*(FILE**)&stream, p);
  g_param_clear(p);
  cm_info_clear(cm);
  for(unsigned int i=0; i<darraySize; ++i)
	cm_info_clear(L[randomIndex]);
  darray_clear(L);
}
*/

// Dump the pairing to stdout
//void Pairing::dump(FILE *f, char *label) const{
  //pairing dumping is yet not available in PBC
//}	
