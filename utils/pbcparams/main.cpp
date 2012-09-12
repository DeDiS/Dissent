#include <QTextStream>
#include <pbc/pbc.h>

int main(int argc, char* argv[]) {
  QTextStream err(stderr, QIODevice::WriteOnly);
  if(argc != 2) {
    err << "Usage: " << argv[0] << " qbits\n";
    return 1;
  }

  int qbits;
  QTextStream in(argv[1], QIODevice::ReadOnly);
  in >> qbits;

  if(qbits < 10) {
    err << "qbits must be greater than 10\n";
    return 1;
  }

  QTextStream out(stdout, QIODevice::WriteOnly);
  out << "--- PBC Parameter Utility ---\n";
  out << "r < q (for prime r and q)\n";
  out << "Bits: " << qbits << "\n";
  out << "\n\n";
  out.flush();

  pbc_param_t params;
  pairing_t pairing;
  pbc_param_init_a_gen(params, qbits, qbits-2);
  pbc_param_out_str(stdout, params);

  pairing_init_pbc_param(pairing, params);

  element_t gen1;
  element_t neg1;
  element_t gent;

  element_t tmp, tmp2;
  element_init_G1(tmp, pairing);
  element_init_G1(tmp2, pairing);
  element_init_Zr(neg1, pairing);

  element_init_G1(gen1, pairing);
  element_init_G1(gent, pairing);

  // neg1 = 1
  element_set1(neg1);
  // neg1 = -1 mod r
  element_neg(neg1, neg1);

  do {
    element_random(gen1);

    // tmp = gen1^-1
    element_pow_zn(tmp, gen1, neg1);
    // tmp = (gen1^-1)*gen1 == gen1^r
    element_mul(tmp2, tmp, gen1);

  } while (!element_is1(tmp2)); 

  element_fprintf(stdout, "g1 = %B\n", gen1);

  do {
    element_random(gent);

    // tmp = gen1^-1
    element_pow_zn(tmp, gent, neg1);
    // tmp = (gen1^-1)*gen1 == gen1^r
    element_mul(tmp2, tmp, gent);

  } while (!element_is1(tmp2));

  element_fprintf(stdout, "gT = %B\n", gent);

  element_clear(gen1);
  element_clear(gent);

  element_clear(tmp);
  element_clear(tmp2);
  element_clear(neg1);

  pbc_param_clear(params);
  pairing_clear(pairing);

  return 0;
}

