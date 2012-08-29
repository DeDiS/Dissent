#ifndef DISSENT_CRYPTO_BLOGDROP_SERVER_CIPHERTEXT_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_SERVER_CIPHERTEXT_H_GUARD

#include "Crypto/AbstractGroup/Element.hpp"
#include "Crypto/Integer.hpp"
#include "ClientCiphertext.hpp"
#include "Parameters.hpp"
#include "PrivateKey.hpp"
#include "PublicKeySet.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding BlogDrop server ciphertext
   */
  class ServerCiphertext {

    public:

      typedef Dissent::Crypto::AbstractGroup::Element Element;

      /**
       * Constructor: Initialize a ciphertext
       * @param params Group parameters
       * @param author_pub Author public key
       * @param n_elms number of elements per ciphertext */
      ServerCiphertext(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKey> author_pub,
          int n_elms);

      /**
       * Destructor
       */
      virtual ~ServerCiphertext() {}

      /**
       * Initialize elements proving correctness of ciphertext
       * @param phase transmisssion round/phase index
       * @param Server private key used to generate proof
       */
      virtual void SetProof(int phase, const QSharedPointer<const PrivateKey> priv) = 0;

      /**
       * Check ciphertext proof
       * @param phase transmisssion round/phase index
       * @param pub public key of server
       * @returns true if proof is okay
       */
      virtual bool VerifyProof(int phase, const QSharedPointer<const PublicKey> pub) const = 0;

      /**
       * Get serialized version
       */
      virtual QByteArray GetByteArray() const = 0;

      virtual inline QList<Element> GetElements() const { return _elements; }
      virtual inline QSharedPointer<const PublicKey> GetAuthorKey() const { return _author_pub; }
      virtual inline QSharedPointer<const Parameters> GetParameters() const { return _params; }

    protected:

      QSharedPointer<const Parameters> _params;
      QSharedPointer<const PublicKey> _author_pub;
      QList<Element> _elements;
      const int _n_elms;
  };
}
}
}

#endif
