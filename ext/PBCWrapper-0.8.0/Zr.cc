#include "Zr.h"
#include <cstring>
#include "PBCExceptions.h"

 //Create and initialize an element
Zr::Zr(const Pairing &e){
  elementPresent = e.isPairingPresent();
  if(elementPresent){
	element_init_Zr(r, *(pairing_t*)&e.getPairing());
  }else throw UndefinedPairingException();
}
  //Create an identity or a random element
Zr::Zr(const Pairing &e, bool random){ 
  elementPresent = e.isPairingPresent();
  if(elementPresent){
	element_init_Zr(r, *(pairing_t*)&e.getPairing());
	if (random)
	  element_random(r);
  }else throw UndefinedPairingException();
}

//Create an element from long int 
Zr::Zr(const Pairing &e, long int i){
  elementPresent = e.isPairingPresent();
  if(elementPresent){
	element_init_Zr(r, *(pairing_t*)&e.getPairing());
	element_set_si(r,i);
  }else throw UndefinedPairingException();
}

//Create an element from GMP integer
Zr::Zr(const Pairing &e, mpz_t z){
  elementPresent = e.isPairingPresent();
  if(elementPresent){
	element_init_Zr(r, *(pairing_t*)&e.getPairing());
	element_set_mpz(r,z);
  }else throw UndefinedPairingException();
}

//Create an element from import
//Traditional Import, bool is not imported
Zr::Zr(const Pairing &e, const unsigned char *data, 
	 unsigned short len, unsigned short base){
  elementPresent = e.isPairingPresent();
  if(elementPresent){
	element_init_Zr(r, *(pairing_t*)&e.getPairing());
	if( base == 16){
	  if(!element_from_bytes(r,*(unsigned char**)&data))
		throw CorruptDataException();}
	else{
	  char *tmp = new char[len+1];
	  strncpy(tmp,(const char*)data,len);
	  tmp[len] = '\0';
	  if(!element_set_str(r, tmp, base)){
		delete[] tmp;
		throw CorruptDataException();
	  }
	  delete[] tmp;
	}
  }else throw UndefinedPairingException();
}

  //Create an element from hash
Zr::Zr(const Pairing &e, const void *data, 
	   unsigned short len){
  elementPresent = e.isPairingPresent();
  if(elementPresent){
	element_init_Zr(r, *(pairing_t*)&e.getPairing());
	element_from_hash(r, *(void**)&data, len);
  }else throw UndefinedPairingException();
}

//Initializes as another element, but with different value
Zr::Zr(const Zr &s, long int i){
  elementPresent = s.isElementPresent();
  if(elementPresent){
	element_init_same_as(r, *(element_t*)&s.getElement());
	element_set_si(r, i);
  }
}
  //Copy constructor
Zr::Zr(const Zr &s){
  elementPresent = s.isElementPresent();
  if(elementPresent){
	element_init_same_as(r, *(element_t*)&s.getElement());
	element_set(r, *(element_t*)&s.getElement());
  }
}

  //Destructor
Zr::~Zr(){
  nullify();
}

//Delete the contents of the elements
void Zr::nullify(){
  if (elementPresent){
	element_clear(r);
	elementPresent = false;
  }
}

  // Assignment operator 
Zr& Zr::operator=(const Zr &rhs){  
//Check for self assignment
  if (this == &rhs) return *this;
  nullify();
  elementPresent = rhs.isElementPresent();
  if(elementPresent){
	element_init_same_as(r,*(element_t*)&rhs.getElement());
	element_set(r,*(element_t*)&rhs.getElement());
  }
  return *this;
}

//Arithmetic Assignment Operators
Zr& Zr::operator+=(const Zr &rhs){
  if(elementPresent && rhs.isElementPresent()){
	element_add(r,r,*(element_t*)&rhs.getElement());
	return *this;
  }else throw UndefinedElementException();
}

Zr& Zr::operator-=(const Zr &rhs){
  if(elementPresent && rhs.isElementPresent()){
	element_sub(r,r, *(element_t*)&rhs.getElement());
	return *this;
  }else throw UndefinedElementException();
}

Zr& Zr::operator*=(const Zr &rhs){
  if(elementPresent && rhs.isElementPresent()){
	element_mul(r,r, *(element_t*)&rhs.getElement());
	return *this;
  }else throw UndefinedElementException();
}
Zr& Zr::operator/=(const Zr &rhs){  
  if(elementPresent && rhs.isElementPresent()){
	element_div(r,r, *(element_t*)&rhs.getElement());	
	return *this;
  }else throw UndefinedElementException();
}
Zr& Zr::operator^=(const Zr &rhs){
  if(elementPresent && rhs.isElementPresent()){
	element_pow_zn(r, r, *(element_t*)&rhs.getElement());
	return *this;
  }else throw UndefinedElementException();
}

bool Zr::operator==(const Zr &rhs) const{
  if(elementPresent && rhs.isElementPresent()){
	return !(element_cmp( *(element_t*)&r,
						*(element_t*)&rhs.getElement()));
  }else throw UndefinedElementException();
}

bool Zr::isIdentity(bool additive) const{
  if (elementPresent){
	if(additive)
	  return (bool) element_is0(*(element_t*)&r);
	else
	  return (bool) element_is1(*(element_t*)&r);
  } else throw UndefinedElementException();
}

const Zr Zr::inverse(bool additive) const{
  if (elementPresent){
	Zr s(*this);
	if (additive)
	  element_neg(*(element_t*)&s.getElement(),
				  *(element_t*)&s.getElement());
	else
	  element_invert(*(element_t*)&s.getElement(),
					 *(element_t*)&s.getElement());
	return s;
  } else throw UndefinedElementException();
}

const Zr Zr::square() const{
  if (elementPresent){
	Zr s(*this);
	element_square(*(element_t*)&s.getElement(),
				   *(element_t*)&s.getElement());
	return s;
  } else throw UndefinedElementException();

}

void Zr::setElement(const element_t& el){
  nullify();
  element_init_same_as(r,*(element_t*)&el);
  elementPresent = true;
  element_set(r,*(element_t*)&el);
}

/*
//Set element from hash
void Zr::setElement(const Pairing &e, const void* data, unsigned short len){
  if(len > 0){
	if(e.isPairingPresent()){
	  nullify();
	  element_init_Zr(r, *(pairing_t*)&e.getPairing());
	  elementPresent = True;
	  element_from_hash(r, *(void**)&data, len);
	} else throw UndefinedPairingException();
  } else throw CorruptDataException();
}

//Set element from import
void Zr::setElement(const Pairing &e, const unsigned char *data, 
					unsigned short len, unsigned short base){
  if(len > 0){
	nullify();	
	elementPresent = data[0];++data;--len;
	if(elementPresent){
	  if(e.isPairingPresent()){
		element_init_Zr(r, *(pairing_t*)&e.getPairing());
		//if (compressed)
		//  element_from_bytes_compressed(g,*(unsigned char**)&data);
		//else
		if( base == 16){
		  if(!element_from_bytes(r,*(unsigned char**)&data))
			throw CorruptDataException();}
		else{
		  char *tmp = new char[len+1];
		  strncpy(tmp,*(char**)&data,len);
		  tmp[len] = '\n';
		  if(!element_set_str(r, tmp, base)){
			delete[] tmp;
			throw CorruptDataException();
		  }
		  delete[] tmp;
		}	  
	  }else throw UndefinedPairingException();
	}
  } else throw CorruptDataException();
}

//Set an element from long int
void Zr::setElement(const Pairing &e, long int i){
  if(e.isPairingPresent()){
	nullify();
	element_init_Zr(r, *(pairing_t*)&e.getPairing());
	elementPresent = True;
	element_set_si(r,i);
  } else throw UndefinedPairingException();
}
*/

const element_t& Zr::getElement() const{
  if (elementPresent)
	return r;
  else
	throw UndefinedElementException();
}

unsigned short Zr::getElementSize() const{
  if (elementPresent)
	return (unsigned short)
	  element_length_in_bytes(*(element_t*)&r)+1;
  //1 is added to take care of bool used
  else throw UndefinedElementException();
}

string Zr::toString() const {
  string str;
  //unsigned char buf[1];
  //buf[0] = elementPresent & 0xff;
  //str.append((char*)buf,1);
  if(elementPresent){
	short len = element_length_in_bytes(*(element_t*)&r);
	unsigned char data[len];
	element_to_bytes(data,*(element_t*)&r);
	str.append((char*)data,len);
  }
  return str;
}

// Dump the element to stdout
void Zr::dump(FILE *f, const char *label, 
			  unsigned short base) const{
 if (label) fprintf(f, "%s: ", label);
 //fprintf(f, "[ ");
  if(elementPresent)
	element_out_str(f, base,*(element_t*)&r);
  else
	fprintf(f,"Element not defined.");
  // fprintf(f, "]\n");
  fprintf(f, "\n");
}	
