#include "G.h"
#include "PBCExceptions.h"

//Intialize with another element and assign identity or same element
G::G(const G &h, bool identity){
  elementPresent = h.isElementPresent();
  if(elementPresent){
	element_init_same_as(g, *(element_t*)&h.getElement());
	if(identity)
	  element_set1(g);
	else
	  element_set(g,*(element_t*)&h.getElement());
  }
}

//Copy constructor
/*G::G(const G &h){
  elementPresent = h.isElementPresent();
  if(elementPresent){
	element_init_same_as(g, *(element_t*)&h.getElement());
	element_set(g,*(element_t*)&h.getElement());
  }
  }*/

//Destructor
G::~G(){
  nullify();
}

//Delete the contents of the elements
void G::nullify(){
  if(elementPresent){
	element_clear(g);
	elementPresent = false;
  }
}

// Assignment operators: 
G& G::operator=(const G &rhs){
  //Check for self assignment
  if (this == &rhs) return *this;
  nullify();
  elementPresent = rhs.isElementPresent();
  if(elementPresent){
	element_init_same_as(g, *(element_t*)& 
						 rhs.getElement());
	element_set(g, *(element_t*)&rhs.getElement());
  }
  return *this;
}

//Arithmetic Assignment Operators
G& G::operator*=(const G &rhs){
  if(elementPresent && rhs.isElementPresent()){
	element_mul(g,g, *(element_t*)&rhs.getElement());
	return *this;
  }else throw UndefinedElementException();
}

G& G::operator/=(const G &rhs){
  if(elementPresent && rhs.isElementPresent()){
	element_div(g,g, *(element_t*)&rhs.getElement());	
	return *this;
  }else throw UndefinedElementException();
}

G& G::operator^=(const Zr &exp){
  if(elementPresent && exp.isElementPresent()){
	element_pow_zn(g, g, *(element_t*)&exp.getElement());
	return *this;
  }else throw UndefinedElementException();
}

bool G::operator==(const G &rhs) const{
  if(elementPresent && rhs.isElementPresent()){
	return !(element_cmp(*(element_t*)&g,
					   *(element_t*)&rhs.getElement()));
  }else throw UndefinedElementException();
}

bool G::isIdentity() const{
  if (elementPresent)
	return element_is1(*(element_t*)&g);
  else
	throw UndefinedElementException();
}

const G G::inverse()const {
  if (elementPresent){
	G h(*this);
	element_invert(*(element_t*)&h.getElement(),
				   *(element_t*)&h.getElement());
	return h;
  }
  else
	throw UndefinedElementException();
}

const G G::square()const {
  if (elementPresent){
	G h(*this);
	element_square(*(element_t*)&h.getElement(),
				   *(element_t*)&h.getElement());
	return h;
  }else
	throw UndefinedElementException();
}

void G::setElement(const element_t& el){
  nullify();
  element_init_same_as(g, *(element_t*)&el);
  elementPresent = true;
  element_set(g, *(element_t*)&el);
}

/*
//Set element from hash
void G::setElement(const void* data,  unsigned short len){
  if(elementPresent)
	element_from_hash(g, *(void**)&data, len);
  else
	throw UndefinedElementException();
}

//Set element from import
void G::setElement(const unsigned char *data, unsigned short len, 
				   bool compressed, unsigned short base){
  if(elementPresent){
	if (compressed){
	  if(!element_from_bytes_compressed(g,*(unsigned char**)&data))
		throw CorruptDataException();}
	else {
	  if( base == 16){
		if(!element_from_bytes(g,*(unsigned char**)&data))
		  throw CorruptDataException();}
	  else{
		char *tmp = new char[len+1];
		strncpy(tmp,*(char**)&data,len);
		tmp[len] = '\0';
		if (!element_set_str(g, tmp, base)){
		  delete[] tmp;
		  throw CorruptDataException();
		}
		delete[] tmp;
	  }
	}
  } else throw UndefinedElementException();
}
*/

const element_t& G::getElement() const{
  if (elementPresent)
	return g;
  else
	throw UndefinedElementException();
}

unsigned short G::getElementSize() const{
  if (elementPresent)
	return (unsigned short)
	  element_length_in_bytes(*(element_t*)&g);
  else
	throw UndefinedElementException();
}

string G::toString() const {
  string str;
  //unsigned char buf[1];
  //buf[0] = elementPresent & 0xff;
  //str.append((char*)buf,1);
  if(elementPresent){
	size_t len = element_length_in_bytes(*(element_t*)&g);
	unsigned char data[len];
	element_to_bytes(data, *(element_t*)&g);
	str.append((char*)data,len);
  }
  return str;
}

// Dump the element to stdout
void G::dump(FILE *f, const char *label,
			 unsigned short base) const{
  if (label) fprintf(f, "%s: ", label);
  if(elementPresent){
	//fprintf(f,"%hu ",base);
	//Here, I need to add size which is a 
	//return value of element_out_str, so that I can
	//use that to obtain data buffer size in the G1, G2, GT and Zr constructors
	element_out_str(f, base, *(element_t*)&g);
  } else
	fprintf(f,"Element_Not_Defined.");
  fprintf(f,"\n");
}	

// Dump the element to a string
int G::dump(char* buf, int buflen) const{
  return element_snprintf(buf, buflen, "%B", *(element_t*)&g);
}
