
#include "Crypto/AbstractGroup/Element.hpp"
#include "Crypto/CryptoFactory.hpp"

#include "BlogDropUtils.hpp"
#include "ServerCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  ServerCiphertext::ServerCiphertext(const QSharedPointer<const Parameters> params,
      const QSharedPointer<const PublicKey> author_pub, 
      int n_elms) :
    _params(params),
    _author_pub(author_pub),
    _n_elms(n_elms)
  {}

}
}
}
