#include "PPPairing.h"
#include "G1.h"
#include "G2.h"
#include "GT.h"
#include "PBCExceptions.h"


PPPairing:: PPPairing(const Pairing &e, const G1 &p): pairing(e) {
  if(e.isPairingPresent())
	if (p.isElementPresent()){
	  pairing_pp_init(pp, *(element_t*)&p.getElement(), 
					  *(pairing_t*)&e.getPairing());
	}else throw UndefinedElementException();
  else throw UndefinedPairingException();
}

PPPairing:: ~PPPairing(){
  pairing_pp_clear(pp);
}

const GT PPPairing:: operator()(const G2 &q) const{
  if (q.isElementPresent()){
	element_t gt;
	element_init_GT(gt,*(pairing_t*)&pairing.getPairing());
	pairing_pp_apply(gt, *(element_t*)&q.getElement(), 
					 *(pairing_pp_t*)&pp);
	GT ans;
	ans.setElement(gt);
	element_clear(gt);
	return ans;
  }	else throw UndefinedElementException();

}

const GT PPPairing:: operator()(const G1 &q) const{
  if (q.isElementPresent())
	if(pairing.isSymmetric()){
	  element_t gt;
	  element_init_GT(gt,*(pairing_t*)&pairing.getPairing());
	  pairing_pp_apply(gt, *(element_t*)&q.getElement(), 
					   *(pairing_pp_t*)&pp);
	  GT ans;
	  ans.setElement(gt);
	  element_clear(gt);
	  return ans;
	} else throw NonsymmetricPairingException();
  else throw UndefinedElementException();
}
