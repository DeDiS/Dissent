#ifndef DISSENT_CRYPTO_BLOGDROP_SERVER_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_SERVER_H_GUARD

#include <QList>
#include <QSharedPointer>

#include "ClientCiphertext.hpp"
#include "Parameters.hpp"
#include "Plaintext.hpp"
#include "PrivateKey.hpp"
#include "PublicKeySet.hpp"
#include "ServerCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  class BlogDropServer {

    public:

      /**
       * Constructor: Initialize a BlogDrop client bin
       * @param params Group parameters
       * @param server_pk_set server public keys
       * @param author_pub author public key
       * @param server_priv server private key
       */
      explicit BlogDropServer(const QSharedPointer<const Parameters> params,  
          const QSharedPointer<const PrivateKey> server_priv,
          const QSharedPointer<const PublicKeySet> server_pk_set,
          const QSharedPointer<const PublicKey> author_pub);

      /**
       * Destructor
       */
      virtual ~BlogDropServer() {}

      /**
       * Remove all ciphertexts from the bin and prepare for the next
       * round
       */
      void ClearBin(); 

      /**
       * Add a client ciphertext. 
       * @param serialized ciphertext to add
       * @param pub client public key
       */
      bool AddClientCiphertext(QByteArray in, QSharedPointer<const PublicKey> pub);

      /**
       * Add a list of client ciphertexts. Silently discards invalid
       * ciphertexts. Uses threading (where available) to speed up
       * the proof verification process.
       * @param in the list of ciphertexts to add
       * @param pubs in the list of client public keys
       */
      bool AddClientCiphertexts(const QList<QByteArray> &in, 
          const QList<QSharedPointer<const PublicKey> > &pubs);

      /**
       * Reveal server ciphertext corresponding to added client
       * ciphertexts
       */
      QByteArray CloseBin();

      /**
       * Add a server ciphertext and return true if the added 
       * ciphertext is valid
       * WARNING : You must call CloseBin() before calling this method
       * @param from public key of the server who sent the ciphertext
       * @param in the serializd server ciphertext to add
       */
      bool AddServerCiphertext(const QSharedPointer<const PublicKey> from, 
          const QByteArray &in);

      /**
       * Reveal plaintext for a BlogDrop bin
       * @param out the returned plaintext
       */
      bool RevealPlaintext(QByteArray &out) const; 

      /**
       * Get public key for this server
       */
      inline QSharedPointer<const PublicKey> GetPublicKey() const {
        return QSharedPointer<const PublicKey>(new PublicKey(_server_priv));
      }

    private:

      int _phase;

      QSharedPointer<const Parameters> _params;
      QSharedPointer<const PrivateKey> _server_priv;
      QSharedPointer<const PublicKeySet> _server_pk_set;
      QSharedPointer<const PublicKey> _author_pub;

      /* list[client] = ciphertext */
      QList<QSharedPointer<const ClientCiphertext> > _client_ciphertexts;
      QList<QSharedPointer<const PublicKey> > _client_pubs;
      QList<QSharedPointer<const ServerCiphertext> > _server_ciphertexts;

      QSharedPointer<const PublicKeySet> _client_pks;
  };
}
}
}

#endif
