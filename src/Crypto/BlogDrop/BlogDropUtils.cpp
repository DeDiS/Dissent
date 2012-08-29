
#include "Crypto/AbstractGroup/AbstractGroup.hpp"
#include "Crypto/AbstractGroup/Element.hpp"

#include "BlogDropUtils.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  Integer BlogDropUtils::Commit(const QSharedPointer<const Parameters> &params,
      const QList<Element> &gs, 
      const QList<Element> &ys, 
      const QList<Element> &ts) 
  {
    Hash *hash = CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();

    hash->Restart();
    hash->Update(params->GetByteArray());

    Q_ASSERT(gs.count() == ys.count());
    Q_ASSERT(gs.count() == ts.count());

    for(int i=0; i<gs.count(); i++) {
      QSharedPointer<const Crypto::AbstractGroup::AbstractGroup> group = 
        ((!i) ? params->GetKeyGroup() : params->GetMessageGroup());

      hash->Update(group->ElementToByteArray(gs[i]));
      hash->Update(group->ElementToByteArray(ys[i]));
      hash->Update(group->ElementToByteArray(ts[i]));
    }

    return Integer(hash->ComputeHash()) % params->GetGroupOrder();
  }

  Integer BlogDropUtils::Commit(const QSharedPointer<const Parameters> &params,
      const Element &g, 
      const Element &y, 
      const Element &t)
  {
    QList<Element> gs;
    gs.append(g);

    QList<Element> ys;
    ys.append(y);

    QList<Element> ts;
    ts.append(t);

    return Commit(params, gs, ys, ts);
  }

  Integer BlogDropUtils::GetPhaseHash(QSharedPointer<const Parameters> params,
      const QSharedPointer<const PublicKey> author_pk, 
      int phase, 
      int element_idx) 
  {
    Hash *hash = CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();
    hash->Restart();
    hash->Update(params->GetByteArray());
    hash->Update(params->GetKeyGroup()->ElementToByteArray(author_pk->GetElement()));
    hash->Update(
        QString("%1 %2").arg(phase, 8, 16, QChar('0')).arg(
          element_idx, 8, 16, QChar('0')).toAscii());

    return Integer(hash->ComputeHash()) % params->GetGroupOrder();
  }

  AbstractGroup::Element BlogDropUtils::GetPairedBase(QSharedPointer<const Parameters> params,
      QHash<int, Element> &cache, 
      const QSharedPointer<const PublicKeySet> prod_pks, 
      const QSharedPointer<const PublicKey> author_pk, 
      int phase, 
      int element_idx) 
  {
    Q_ASSERT(params->UsesPairing());
    if(cache.contains(element_idx)) return cache[element_idx];

    // e(server_pks, tau)
    const Integer exp = GetPhaseHash(params, author_pk, phase, element_idx);
    const Element tau = params->GetKeyGroup()->Exponentiate(
        params->GetKeyGroup()->GetGenerator(), exp);

    Element base = params->ApplyPairing(prod_pks->GetElement(), tau);
    cache[element_idx] = base;
    return base;
  }

  AbstractGroup::Element BlogDropUtils::GetHashedGenerator(
      QSharedPointer<const Parameters> params,
      QHash<int, Element> &cache, 
      const QSharedPointer<const PublicKey> author_pk, 
      int phase, 
      int element_idx) 
  {
    if(cache.contains(element_idx)) return cache[element_idx];

    // g^hash
    const int bytes = params->GetMessageGroup()->BytesPerElement() - 1;
    Integer nonce = GetPhaseHash(params, author_pk, phase, element_idx);
    qDebug() << "orig" << nonce.GetByteArray().toHex();

    qDebug() << "nbytes" << (bytes);
    nonce = nonce % (Integer(2).Pow(bytes*8, params->GetMessageGroup()->GetOrder()));
    qDebug() << nonce.GetByteArray().toHex();

    const QByteArray nonce_str = nonce.GetByteArray();

    Element gen;
    int i;
    for(i=0; i<255; i++) {
      qDebug() << "hash" << i;
      qDebug() << (nonce_str + QByteArray(1, i)).toHex();
      gen = params->GetMessageGroup()->EncodeBytes(nonce_str + QByteArray(1, i)); 
      if(params->GetMessageGroup()->IsGenerator(gen)) break;
    }

    if(i > 250) qFatal("Failed to find generator");

    cache[element_idx] = gen;
    return gen;
  }
}
}
}
