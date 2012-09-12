#include "GT.h"
#include <cstring>
#include "PBCExceptions.h"

//Create and initialize an element
GT::GT(const Pairing &e): G(e){
  if(elementPresent){
	element_init_GT(g, *(pairing_t*)&e.getPairing());
  }else throw UndefinedPairingException();
}

//Create an identity or a random element
GT::GT(const Pairing &e, bool identity): G(e){
  if(elementPresent){
	element_init_GT(g, *(pairing_t*)&e.getPairing());
	if (identity)
	  element_set1(g);
	else
	  element_random(g);
  }else throw UndefinedPairingException();
}

//Create an element from import 
GT::GT(const Pairing &e, const unsigned char *data, 
	   unsigned short len, unsigned short base, bool use_binary): G(e){
  if(elementPresent){
	element_init_GT(g, *(pairing_t*)&e.getPairing());
	//if (compressed)
	//  element_from_bytes_compressed(g,*(unsigned char**)&data);
	//else
	if(use_binary){
	  if(!element_from_bytes(g,*(unsigned char**)&data))
		throw CorruptDataException();}
	else{
	  char *tmp = new char[len+1];
	  strncpy(tmp,(const char*)data,len);
	  tmp[len] = '\0';
	  if(!element_set_str(g, tmp, base)){
		delete[] tmp;
		throw CorruptDataException();
	  }
	  delete[] tmp;
	}
  }else throw UndefinedPairingException();
}

//Create an element from hash
GT::GT(const Pairing &e, const void *data, 
	   unsigned short len): G(e){
  if(elementPresent){
	element_init_GT(g, *(pairing_t*)&e.getPairing());
	element_from_hash(g,  *(void**)&data, len);
  }else throw UndefinedPairingException();
}


