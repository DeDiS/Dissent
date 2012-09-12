#include <QByteArray>

#include <pbc/pbc.h>

#include "Crypto/AbstractGroup/ByteGroup.hpp"
#include "Crypto/AbstractGroup/CppECGroup.hpp"
#include "Crypto/AbstractGroup/IntegerGroup.hpp"
#include "Crypto/AbstractGroup/OpenECGroup.hpp"
#include "Crypto/AbstractGroup/PairingG1Group.hpp"
#include "Crypto/AbstractGroup/PairingGTGroup.hpp"
#include "Parameters.hpp"

using namespace Dissent::Crypto::AbstractGroup;

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  QSharedPointer<Parameters> Parameters::IntegerElGamalTestingFixed() 
  {
    QSharedPointer<const AbstractGroup> fixed = IntegerGroup::TestingFixed();
    return QSharedPointer<Parameters>(
        new Parameters(ProofType_ElGamal, QByteArray(), fixed, fixed, 2));
  }

  QSharedPointer<Parameters> Parameters::IntegerElGamalProductionFixed(QByteArray round_nonce) 
  {
    QSharedPointer<const AbstractGroup> fixed = IntegerGroup::Production2048Fixed();
    return QSharedPointer<Parameters>(
        new Parameters(ProofType_ElGamal, round_nonce, fixed, fixed, 1));
  }

  QSharedPointer<Parameters> Parameters::IntegerHashingTestingFixed() 
  {
    QSharedPointer<const AbstractGroup> fixed = IntegerGroup::TestingFixed();
    return QSharedPointer<Parameters>(
        new Parameters(ProofType_HashingGenerator, QByteArray(), fixed, fixed, 2));
  }

  QSharedPointer<Parameters> Parameters::IntegerHashingProductionFixed(QByteArray round_nonce) 
  {
    QSharedPointer<const AbstractGroup> fixed = IntegerGroup::Production2048Fixed();
    return QSharedPointer<Parameters>(
        new Parameters(ProofType_HashingGenerator, round_nonce, fixed, fixed, 1));
  }

  QSharedPointer<Parameters> Parameters::CppECElGamalProductionFixed(QByteArray round_nonce) 
  {
    QSharedPointer<const AbstractGroup> fixed = CppECGroup::ProductionFixed();
    return QSharedPointer<Parameters>(
        new Parameters(ProofType_ElGamal, round_nonce, fixed, fixed, 8));
  }

  QSharedPointer<Parameters> Parameters::CppECHashingProductionFixed(QByteArray round_nonce) 
  {
    QSharedPointer<const AbstractGroup> fixed = CppECGroup::ProductionFixed();
    return QSharedPointer<Parameters>(
        new Parameters(ProofType_HashingGenerator, round_nonce, fixed, fixed, 8));
  }

  QSharedPointer<Parameters> Parameters::OpenECElGamalProductionFixed(QByteArray round_nonce) 
  {
    QSharedPointer<const AbstractGroup> fixed = OpenECGroup::ProductionFixed();
    return QSharedPointer<Parameters>(
        new Parameters(ProofType_ElGamal, round_nonce, fixed, fixed, 8));
  }

  QSharedPointer<Parameters> Parameters::OpenECHashingProductionFixed(QByteArray round_nonce) 
  {
    QSharedPointer<const AbstractGroup> fixed = OpenECGroup::ProductionFixed();
    return QSharedPointer<Parameters>(
        new Parameters(ProofType_HashingGenerator, round_nonce, fixed, fixed, 8));
  }

  QSharedPointer<Parameters> Parameters::PairingProductionFixed(QByteArray round_nonce) 
  {
    QSharedPointer<const AbstractGroup> g1 = PairingG1Group::ProductionFixed();
    QSharedPointer<const AbstractGroup> gT = PairingGTGroup::ProductionFixed();
    return QSharedPointer<Parameters>(
        new Parameters(ProofType_Pairing, round_nonce, g1, gT, 4));
  }
  
  QSharedPointer<Parameters> Parameters::XorTestingFixed(QByteArray round_nonce) 
  {
    QSharedPointer<const AbstractGroup> g1 = ByteGroup::TestingFixed();
    QSharedPointer<const AbstractGroup> gT = ByteGroup::TestingFixed();
    return QSharedPointer<Parameters>(
        new Parameters(ProofType_Xor, round_nonce, g1, gT, 2));
  }

  QSharedPointer<Parameters> Parameters::Empty() 
  {
    return QSharedPointer<Parameters>(new Parameters());
  }

  Parameters::Parameters() : 
    _proof_type(ProofType_Invalid),
    _n_elements(0) {}

  Parameters::Parameters(ProofType proof_type, 
      QByteArray round_nonce,
      QSharedPointer<const AbstractGroup> key_group, 
      QSharedPointer<const AbstractGroup> msg_group, 
      int n_elements) :
    _proof_type(proof_type),
    _round_nonce(round_nonce),
    _key_group(key_group),
    _msg_group(msg_group),
    _n_elements(n_elements)
  {
    Q_ASSERT(!_key_group.isNull());
    Q_ASSERT(!_msg_group.isNull());
    Q_ASSERT(key_group->IsProbablyValid());
    Q_ASSERT(msg_group->IsProbablyValid());
  }
  
  QByteArray Parameters::GetByteArray() const
  {
    QByteArray out;
    out += GetRoundNonce();
    out += GetKeyGroup()->GetByteArray();
    out += GetMessageGroup()->GetByteArray();
    out += _n_elements;
    return out;
  }

  Element Parameters::ApplyPairing(const Element &a, const Element &b) const 
  {
    if(!UsesPairing()) qFatal("Parameters do not use pairing");

    const PairingGTGroup *gTp = dynamic_cast<const PairingGTGroup*>(GetMessageGroup().data());
    Q_ASSERT(gTp);

    return gTp->ApplyPairing(a, b);
  }

  QString Parameters::ProofTypeToString(ProofType pt)
  {
    QString out; 
    switch(pt) {
      case ProofType_ElGamal:
        out = "ElGamal";
        break;

      case ProofType_HashingGenerator:
        out = "HashingGenerator";
        break;

      case ProofType_Pairing:
        out = "Pairing";
        break;

      case ProofType_Xor:
        out = "Xor";
        break;

      case ProofType_Invalid:
        out = "Invalid";
        break;

      default: 
        out = "Unknown";
    }

    return out;
  }

  QString Parameters::ToString() const
  {
    return QString("Parameters<keygroup: %1, "
        "msggroup: %2, "
        "prooftype: %3, "
        "nelms: %4, "
        "nonce: \"%5\">").arg(
          _key_group->ToString()).arg(
          _msg_group->ToString()).arg(
          ProofTypeToString(GetProofType())).arg(
          _n_elements).arg( 
          QString(_round_nonce.toHex()));
  }
}
}
}
