#include <iostream>
#include "PBC.h"

using namespace std;

int main(int argc, char **argv)
{
  const char *paramFileName = (argc > 1) ? argv[1] : "pairing.param";
  FILE *sysParamFile = fopen(paramFileName, "r");
  if (sysParamFile == NULL) {
    cerr<<"Can't open the parameter file " << paramFileName << "\n";
    cerr<<"Usage: " << argv[0] << " [paramfile]\n";
    return 0;
  }
  Pairing e(sysParamFile);
  cout<<"Is symmetric? "<< e.isSymmetric()<< endl;
  cout<<"Is pairing present? "<< e.isPairingPresent()<< endl;  
  fclose(sysParamFile);

  G1 p(e,false);
  p = G1(e, "1234567", 7);
  p.dump(stdout,"Hash for 1234567 is ",10);
  G2 q(e,false);
  Zr r(e,(long int)10121);
  r.dump(stdout,"r",10);
  // Create a random element of Zr
  Zr s(e,true);
  s.dump(stdout,"s",10);
  r =s;
  r.dump(stdout,"new r",10);
  GT LHS = e(p,q)^r;
  G1 pr(p^r);
  p.dump(stdout,"p", 10);
  q.dump(stdout, "q", 10);
  pr.dump(stdout,"p^r", 10);
  GT RHS = e((p^r),q);
  LHS.dump(stdout,"LHS", 10);
  RHS.dump(stdout,"RHS", 10);

  if((e(p,q)^r) == e(p^r,q))
	cout<<"Correct Pairing Computation"<<endl;
  else
	cout<<"Incorrect Pairing Computation"<<endl;
  if((p.inverse()).square() == (p.square()).inverse())
	cout<<"Inverse, Square works"<<endl;
  else
	cout<<"Inverse, Square does not work."<<endl;
  G1 a;
  a = p;
  p.dump(stdout,"p is ") ;
  a.dump(stdout,"a is ") ;
  // Create the identity element b (in the same group as a)
  G1 b(a,true);
  b.dump(stdout,"b is ") ;
  return 0;
}
