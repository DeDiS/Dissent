#ifndef DISSENT_TESTS_ABSTRACT_GROUP_HELPERS_H_GUARD
#define DISSENT_TESTS_ABSTRACT_GROUP_HELPERS_H_GUARD

#include "Dissent.hpp"

namespace Dissent {
namespace Tests {

  typedef Dissent::Crypto::AbstractGroup::AbstractGroup AbstractGroup;

  inline void AbstractGroup_Basic(QSharedPointer<AbstractGroup> group)
  {
    Element g = group->GetGenerator();

    ASSERT_TRUE(group->IsProbablyValid());
    ASSERT_EQ(g, g);
    ASSERT_TRUE(group->IsElement(g));
    ASSERT_TRUE(group->IsIdentity(group->GetIdentity()));
    ASSERT_FALSE(group->IsIdentity(g));
    ASSERT_TRUE(group->IsIdentity(group->Exponentiate(g, group->GetOrder())));
    ASSERT_TRUE(group->IsElement(group->Multiply(g, g)));

    for(int i=0; i<100; i++) {
      Element a = group->RandomElement();
      Element l = group->Exponentiate(group->Inverse(a), Integer(2));
      Element r = group->Inverse(group->Exponentiate(a, Integer(2)));

      EXPECT_EQ(l, r);
    }
  }

  inline void AbstractGroup_IsElement(QSharedPointer<AbstractGroup> group)
  {
    for(int i=0; i<100; i++) {
      Element e = group->RandomElement();
      EXPECT_TRUE(group->IsElement(e));
      EXPECT_FALSE(group->IsIdentity(e));
      EXPECT_FALSE(group->GetGenerator() == e);
    }
  }

  inline void AbstractGroup_RandomExponent(QSharedPointer<AbstractGroup> group)
  {
    for(int i=0; i<100; i++) {
      EXPECT_TRUE(group->IsElement(group->Exponentiate(group->GetGenerator(),
              group->RandomExponent())));
    }
  }

  inline void AbstractGroup_Multiplication(QSharedPointer<AbstractGroup> group)
  {
    for(int i=0; i<100; i++) {
      Element a = group->RandomElement();
      Element b = group->RandomElement();
      Integer c = group->RandomExponent();
      Element ab = group->Multiply(a, b);
      Element a2c = group->Exponentiate(a, c);
      Element b2c = group->Exponentiate(b, c);

      EXPECT_EQ(ab, group->Multiply(b, a));

      // (a*b)^c  ==  (a^c)*(b^c)
      EXPECT_EQ(group->Exponentiate(ab, c), group->Multiply(a2c, b2c));
      EXPECT_EQ(group->Exponentiate(ab, c), group->CascadeExponentiate(a, c, b, c));
    }
  }

  inline void AbstractGroup_Exponentiation(QSharedPointer<AbstractGroup> group)
  {
    for(int i=0; i<100; i++) {
      Element a = group->RandomElement();
      Element b = group->RandomElement();
      Integer c = group->RandomExponent();

      EXPECT_EQ(a, group->Exponentiate(a, Integer(1)));
    }
  }

  inline void AbstractGroup_Serialize(QSharedPointer<AbstractGroup> group)
  {
    for(int i=0; i<100; i++) {
      Element a = group->RandomElement();
      QByteArray b = group->ElementToByteArray(a);
      Element a2 = group->ElementFromByteArray(b);

      EXPECT_EQ(a, a2);
    }
  }

  inline void AbstractGroup_Encode(QSharedPointer<AbstractGroup> group)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    QByteArray out;
    QByteArray msg(group->BytesPerElement(), 0);
    for(int i=0; i<100; i++) {
      rand->GenerateBlock(msg);

      Element a = group->EncodeBytes(msg);
      ASSERT_TRUE(group->DecodeBytes(a, out));

      EXPECT_EQ(msg, out);
    }
  }

}
}

#endif
