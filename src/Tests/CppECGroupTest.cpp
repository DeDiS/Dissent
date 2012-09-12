#include "AbstractGroupHelpers.hpp"
#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  TEST(CppECGroup, Basic)
  {
    AbstractGroup_Basic(CppECGroup::ProductionFixed());
  }

  TEST(CppECGroup, IsElement) 
  {
    AbstractGroup_IsElement(CppECGroup::ProductionFixed());
  }

  TEST(CppECGroup, RandomExponent) 
  {
    AbstractGroup_RandomExponent(CppECGroup::ProductionFixed());
  }

  TEST(CppECGroup, NotElement) 
  {
    QSharedPointer<CppECGroup> group = CppECGroup::ProductionFixed();

    int count = 0;
    for(int i=0; i<100; i++) {
      Integer x = Integer::GetRandomInteger(0, group->GetFieldSize());
      Integer y = Integer::GetRandomInteger(0, group->GetFieldSize());

      CryptoPP::ECPPoint p(CryptoPP::Integer(x.GetByteArray().constData()), 
          CryptoPP::Integer(y.GetByteArray().constData()));
      Element e(new CppECElementData(p));
      if(group->IsElement(e)) count++;
    }

    EXPECT_TRUE(count < 5);
  }
  
  TEST(CppECGroup, Multiplication) 
  {
    AbstractGroup_Multiplication(CppECGroup::ProductionFixed());
  }

  TEST(CppECGroup, Exponentiation) 
  {
    AbstractGroup_Exponentiation(CppECGroup::ProductionFixed());
  }

  TEST(CppECGroup, Serialize)
  {
    AbstractGroup_Serialize(CppECGroup::ProductionFixed());
  }

  TEST(CppECGroup, Encode)
  {
    AbstractGroup_Encode(CppECGroup::ProductionFixed());
  }

}
}
