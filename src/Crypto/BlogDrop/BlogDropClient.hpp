#ifndef DISSENT_CRYPTO_BLOGDROP_CLIENT_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_CLIENT_H_GUARD

#include <QSharedPointer>

#include "Parameters.hpp"
#include "Plaintext.hpp"
#include "PrivateKey.hpp"
#include "PublicKeySet.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  class BlogDropClient {

    public:

      /**
       * Constructor: Initialize a BlogDrop client bin
       * @param params Group parameters
       * @param client_priv client private key
       * @param server_pks Server public keys
       * @param author_pub author public key
       */
      explicit BlogDropClient(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PrivateKey> client_priv,
          const QSharedPointer<const PublicKeySet> server_pks,
          const QSharedPointer<const PublicKey> author_pub);

      /**
       * Destructor
       */
      virtual ~BlogDropClient() {}

      /**
       * Generate a client cover-traffic ciphertext
       */
      QByteArray GenerateCoverCiphertext();

    protected: 

      inline QSharedPointer<const Parameters> GetParameters() const { return _params; }
      inline QSharedPointer<const PrivateKey> GetClientKey() const { return _client_priv; }
      inline QSharedPointer<const PublicKeySet> GetServerKeys() const { return _server_pks; }
      inline QSharedPointer<const PublicKey> GetAuthorKey() const { return _author_pub; }

      inline int GetPhase() const { return _phase; }
      inline void NextPhase() { _phase++; }

    private:

      int _phase;

      QSharedPointer<const Parameters> _params;
      QSharedPointer<const PrivateKey> _client_priv;
      QSharedPointer<const PublicKeySet> _server_pks;
      QSharedPointer<const PublicKey> _author_pub;
  };
}
}
}

#endif
