
#include <QtCore>

#include "Crypto/CryptoFactory.hpp"

#include "BlogDropUtils.hpp"
#include "ClientCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  ClientCiphertext::ClientCiphertext(const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKeySet> server_pks,
      const QSharedPointer<const PublicKey> author_pub,
      int n_elms) :
    _params(params),
    _server_pks(server_pks),
    _author_pub(author_pub),
    _n_elms(n_elms)
  {}

  QSet<int> ClientCiphertext::VerifyProofs(int phase, 
      const QList<QSharedPointer<const ClientCiphertext> > &c,
      const QList<QSharedPointer<const PublicKey> > &pubs)
  {
    Q_ASSERT(pubs.count() == c.count());

    QSet<int> valid;

    for(int idx=0; idx<c.count(); idx++) {
      if(c[idx]->VerifyProof(phase, pubs[idx])) valid.insert(idx);
    }

    return valid;
  }

}
}
}
