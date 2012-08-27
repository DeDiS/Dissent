#ifndef DISSENT_CRYPTO_BLOGDROP_PARAMETERS_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_PARAMETERS_H_GUARD

#include <QByteArray>
#include <QSharedPointer>

#include "Crypto/AbstractGroup/AbstractGroup.hpp"
#include "Crypto/AbstractGroup/PairingWrapper.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding group definition
   */
  class Parameters {

    public:

      typedef Dissent::Crypto::AbstractGroup::AbstractGroup AbstractGroup;
      typedef Dissent::Crypto::AbstractGroup::Element Element;
      typedef Dissent::Crypto::AbstractGroup::PairingWrapper PairingWrapper;

      /**
       * Constructor that uses 512-bit integer group (for testing)
       */
      static QSharedPointer<Parameters> IntegerTestingFixed();

      /**
       * Constructor that uses 1024-bit fixed integer group 
       */
      static QSharedPointer<Parameters> IntegerProductionFixed(QByteArray round_nonce = QByteArray());

      /**
       * Constructor that uses 256-bit fixed EC group 
       * (Supposedly 256-bit ECs are equivalent to 3072-bit 
       * RSA/DH groups) implemented with Crypto++
       */
      static QSharedPointer<Parameters> CppECProductionFixed(QByteArray round_nonce = QByteArray());

      /**
       * Constructor that uses 256-bit fixed EC group 
       * (Supposedly 256-bit ECs are equivalent to 3072-bit 
       * RSA/DH groups) implemented with OpenSSL
       */
      static QSharedPointer<Parameters> OpenECProductionFixed(QByteArray round_nonce = QByteArray());

      /**
       * Constructor that uses a type-A pairing group from
       * the Stanford PBC library
       *   qbits = 512
       *   rbits = 510
       */
      static QSharedPointer<Parameters> PairingProductionFixed(QByteArray round_nonce = QByteArray());
      
      
      /**
       * Constructor that has empty/invalid parameters
       */
      static QSharedPointer<Parameters> Empty();

      /**
       * Destructor
       */
      virtual ~Parameters() {}

      /**
       * Get the group that contains the public key elements 
       */
      inline QSharedPointer<const AbstractGroup> GetKeyGroup() const { return _key_group; }

      /**
       * Get the group that contains the ciphertext and message elements
       */
      inline QSharedPointer<const AbstractGroup> GetMessageGroup() const { 
        return _msg_group;
      }

      /**
       * Get a serialized version of these parameters
       */
      QByteArray GetByteArray() const;

      /**
       * Return true if parameters use a pairing
       */
      bool UsesPairing() const;

      QByteArray GetRoundNonce() const { return _round_nonce; }
      virtual int GetNElements() const { return _n_elements; }
      QSharedPointer<const PairingWrapper> GetPairing() const { return _pairing; }

      inline Integer GetGroupOrder() const { 
        // For proofs to work, the two groups must have the same order
        Q_ASSERT(_key_group->GetOrder() == _msg_group->GetOrder());
        return _key_group->GetOrder();
      }
  
      Element ApplyPairing(const Element &a, const Element &b) const;

    private:

      Parameters();

      Parameters(QByteArray round_nonce, QSharedPointer<const AbstractGroup> key_group, 
          QSharedPointer<const AbstractGroup> msg_group, int n_elements);

      QByteArray _round_nonce;

      /**
       * The group containing the public keys
       */
      QSharedPointer<const AbstractGroup> _key_group;

      /**
       * The group containing the message elements (plaintexts + ciphertexts)
       */
      QSharedPointer<const AbstractGroup> _msg_group;

      /**
       * Pairing (where applicable) of G1 x G1 --> GT
       */
      QSharedPointer<const PairingWrapper> _pairing;

      /**
       * Number of ciphertext elements in a single ciphertext
       */
      const int _n_elements;
  };
}
}
}

#endif
