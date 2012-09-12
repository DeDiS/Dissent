#include "AbstractGroupHelpers.hpp"
#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  TEST(ByteGroup, Basic)
  {
    QSharedPointer<ByteGroup> group = ByteGroup::TestingFixed();
    for(int i=0; i<1000; i++) {
      Element id = group->GetIdentity();
      Element rand = group->RandomElement();
      ASSERT_EQ(id, group->Multiply(rand, rand));
      ASSERT_EQ(id, group->Exponentiate(rand, Integer(4)));
      ASSERT_EQ(rand, group->Exponentiate(rand, Integer(7)));

      ASSERT_FALSE(group->IsIdentity(rand));
      ASSERT_TRUE(group->IsGenerator(rand));
      ASSERT_TRUE(group->IsIdentity(id));
    }
  }

  TEST(ByteGroup, Encode)
  {
    AbstractGroup_Encode(ByteGroup::TestingFixed());
  }

}
}
