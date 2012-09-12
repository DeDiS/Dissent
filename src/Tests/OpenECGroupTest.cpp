#include "AbstractGroupHelpers.hpp"
#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  TEST(OpenECGroup, Basic)
  {
    AbstractGroup_Basic(OpenECGroup::ProductionFixed());
  }

  TEST(OpenECGroup, IsElement) 
  {
    AbstractGroup_IsElement(OpenECGroup::ProductionFixed());
  }

  TEST(OpenECGroup, RandomExponent) 
  {
    AbstractGroup_RandomExponent(OpenECGroup::ProductionFixed());
  }

  TEST(OpenECGroup, Multiplication) 
  {
    AbstractGroup_Multiplication(OpenECGroup::ProductionFixed());
  }

  TEST(OpenECGroup, Exponentiation) 
  {
    AbstractGroup_Exponentiation(OpenECGroup::ProductionFixed());
  }

  TEST(OpenECGroup, Serialize)
  {
    AbstractGroup_Serialize(OpenECGroup::ProductionFixed());
  }

  TEST(OpenECGroup, Encode)
  {
    AbstractGroup_Encode(OpenECGroup::ProductionFixed());
  }

}
}
