
#include "PairingElementData.hpp"
#include "PairingGroup.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {
   // Note that these values are in base-10
   const char PairingGroup::_param_bytes[] = "type a\n"
            "q 80446847579655582597444149989235076764876194923554360266341368662"
            "3305841804412818608112457890014205661401911491189163051225232968716"
            "794196786018682667008059\n"
            "h 60\n"
            "r 13407807929942597099574024998205846127479365820592393377723561443"
            "7217640300735469768018742981669034276900318581864860508537538828119"
            "46569946433644711116801\n"
            "exp2 512\n"
            "exp1 32\n"
            "sign1 -1\n"
            "sign0 1\n";

   // This value is in hex. Note that PBC calls the order "r", while we call it
   // "q."
  const char PairingGroup::_order_bytes[] = 
            "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffff00000001";

  // This value is in hex. Note that PBC calls the field size "q" while we
  // call it p. This is the field size of G1 and G2 in a type-A pairing.
  // The field size for GT is (field_size)^2
  const char PairingGroup::_field_bytes[] = 
            "0x3bfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffc40000003b";

  PairingGroup::PairingGroup() :
    _param_str(QByteArray(_param_bytes)),
    _pairing(_param_str.constData(), _param_str.count()),
    _order(Integer(QByteArray::fromHex(_order_bytes))),
    _field(Integer(QByteArray::fromHex(_field_bytes)))
  {
    Q_ASSERT(_pairing.isPairingPresent());

  };

  PairingGroup::~PairingGroup()
  {}

  Integer PairingGroup::RandomExponent() const
  {
    return Integer::GetRandomInteger(1, GetOrder(), false); 
  }
  
  Zr PairingGroup::IntegerToZr(const Integer &in) const
  { 
    mpz_t z;
    mpz_init(z);
    QByteArray b = in.GetByteArray().toHex();
    const char *bytes = b.constData();
    int ret;

    if((ret = gmp_sscanf(bytes, "%Zx", z)) != 1) {
      //qDebug() << "Bad string of len" << b.count() << ":" << bytes;
      //qDebug() << "Read" << ret;
      qFatal("Could not convert integer");
    }

    Zr e(_pairing, z);
    Q_ASSERT(e.isElementPresent());

    mpz_clear(z);
    return e; 
  }

}
}
}
