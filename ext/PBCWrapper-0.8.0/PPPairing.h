#ifndef __PPPairing_H__
#define __PPPairing_H__

#include "Pairing.h"

class PPPairing {
public:
  PPPairing(const Pairing &e, const G1 &p);
  const GT operator()(const G2 &q) const;

  //For a symmetric pairing
  const GT operator()(const G1 &q) const;

  ~PPPairing();
private:
  pairing_pp_t pp;
  const Pairing &pairing;
};

#endif
