#include "AbstractGroupHelpers.hpp"
#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  TEST(PairingGroupG1, Basic)
  {
    AbstractGroup_Basic(PairingG1Group::ProductionFixed());
  }

  TEST(PairingGroupGT, Basic)
  {
    AbstractGroup_Basic(PairingGTGroup::ProductionFixed());
  }

  TEST(PairingGroupG1, IsElement)
  {
    AbstractGroup_IsElement(PairingG1Group::ProductionFixed());
  }

  TEST(PairingGroupGT, IsElement)
  {
    AbstractGroup_IsElement(PairingGTGroup::ProductionFixed());
  }
  
  TEST(PairingGroupG1, RandomExponent)
  {
    AbstractGroup_RandomExponent(PairingG1Group::ProductionFixed());
  }

  TEST(PairingGroupGT, RandomExponent)
  {
    AbstractGroup_RandomExponent(PairingGTGroup::ProductionFixed());
  }

  TEST(PairingGroupG1, Multiplication)
  {
    AbstractGroup_Multiplication(PairingG1Group::ProductionFixed());
  }

  TEST(PairingGroupGT, Multiplication)
  {
    AbstractGroup_Multiplication(PairingGTGroup::ProductionFixed());
  }

  TEST(PairingGroupG1, Exponentiation)
  {
    AbstractGroup_Exponentiation(PairingG1Group::ProductionFixed());
  }

  TEST(PairingGroupGT, Exponentiation)
  {
    AbstractGroup_Exponentiation(PairingGTGroup::ProductionFixed());
  }

  TEST(PairingGroupG1, Serialize)
  {
    AbstractGroup_Serialize(PairingG1Group::ProductionFixed());
  }

  TEST(PairingGroupGT, Serialize)
  {
    AbstractGroup_Serialize(PairingGTGroup::ProductionFixed());
  }

  /* not implemented yet
  TEST(PairingGroupG1, Encode)
  {
    AbstractGroup_Encode(PairingG1Group::ProductionFixed());
  }
  */

  TEST(PairingGroupGT, Encode)
  {
    AbstractGroup_Encode(PairingGTGroup::ProductionFixed());
  }

  TEST(Pairing, Basic)
  {
    QSharedPointer<PairingG1Group> group1(PairingG1Group::ProductionFixed());
    QSharedPointer<PairingGTGroup> groupT(PairingGTGroup::ProductionFixed());

    ASSERT_EQ(group1->GetByteArray(), groupT->GetByteArray());

    Element a = group1->RandomElement();
    for(int i=0; i<100; i++) {
      Integer r = group1->RandomExponent();

      Element lhs = groupT->ApplyPairing(a, group1->Multiply(a, a));
      EXPECT_FALSE(groupT->IsIdentity(lhs));

      Element rhs = groupT->ApplyPairing(group1->Exponentiate(a, Integer(2)), a);
      EXPECT_FALSE(groupT->IsIdentity(rhs));

      EXPECT_EQ(lhs, rhs);
    }
  }

  TEST(Pairing, Exponent)
  {
    QSharedPointer<PairingG1Group> group1(PairingG1Group::ProductionFixed());
    QSharedPointer<PairingGTGroup> groupT(PairingGTGroup::ProductionFixed());

    ASSERT_EQ(group1->GetByteArray(), groupT->GetByteArray());

    Element a = group1->RandomElement();
    Element b = group1->RandomElement();
    for(int i=0; i<100; i++) {
      Integer r = group1->RandomExponent();

      Element lhs = groupT->ApplyPairing(a, b);
      EXPECT_FALSE(groupT->IsIdentity(lhs));

      Element rhs = groupT->ApplyPairing(b, a);
      EXPECT_FALSE(groupT->IsIdentity(rhs));

      EXPECT_EQ(lhs, rhs);

      lhs = groupT->ApplyPairing(a, group1->Exponentiate(b, r));
      EXPECT_FALSE(groupT->IsIdentity(lhs));

      rhs = groupT->ApplyPairing(group1->Exponentiate(a, r), b);
      EXPECT_FALSE(groupT->IsIdentity(rhs));

      EXPECT_EQ(lhs, rhs);
    }
  }

  TEST(Pairing, DoubleExponent)
  {
    QSharedPointer<PairingG1Group> group1(PairingG1Group::ProductionFixed());
    QSharedPointer<PairingGTGroup> groupT(PairingGTGroup::ProductionFixed());

    ASSERT_EQ(group1->GetByteArray(), groupT->GetByteArray());

    Element a = group1->RandomElement();
    Element b = group1->RandomElement();
    for(int i=0; i<100; i++) {
      Integer ra = group1->RandomExponent();
      Integer rb = group1->RandomExponent();

      Element lhs = groupT->ApplyPairing(group1->Exponentiate(a, ra), group1->Exponentiate(b, rb));
      EXPECT_FALSE(groupT->IsIdentity(lhs));

      Element rhs = groupT->ApplyPairing(b, a);
      rhs = groupT->Exponentiate(rhs, ra);
      rhs = groupT->Exponentiate(rhs, rb);
      EXPECT_FALSE(groupT->IsIdentity(rhs));

      EXPECT_EQ(lhs, rhs);
    }
  }

  TEST(Pairing, EncodeAndPair)
  {
    QSharedPointer<PairingG1Group> group1(PairingG1Group::ProductionFixed());
    QSharedPointer<PairingGTGroup> groupT(PairingGTGroup::ProductionFixed());

    ASSERT_EQ(group1->GetByteArray(), groupT->GetByteArray());

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    QByteArray out;

    for(int i=0; i<100; i++) {
      QByteArray msg(rand->GetInt(1, groupT->BytesPerElement()), 0);
      rand->GenerateBlock(msg);

      Element a = group1->RandomElement();
      Element b = group1->RandomElement();

      Element m = groupT->EncodeBytes(msg);

      // compute c = m * e(a,b) * e(a, b^-1)
      Element t1 = groupT->ApplyPairing(a, b);
      Element t2 = groupT->ApplyPairing(a, group1->Inverse(b));

      Element c = groupT->Multiply(groupT->Multiply(t1, t2), m);

      // check m == c
      EXPECT_EQ(m, c);

      EXPECT_TRUE(groupT->DecodeBytes(c, out));
      EXPECT_EQ(msg, out);
    }
  }
}
}
