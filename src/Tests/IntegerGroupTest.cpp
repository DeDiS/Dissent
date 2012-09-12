#include "AbstractGroupHelpers.hpp"
#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  TEST(IntegerGroup, Basic)
  {
    QList<QSharedPointer<IntegerGroup> > list;

    list.append(QSharedPointer<IntegerGroup>(new IntegerGroup(11, 3)));
    list.append(QSharedPointer<IntegerGroup>(IntegerGroup::TestingFixed()));
    list.append(QSharedPointer<IntegerGroup>(IntegerGroup::Production1024Fixed()));
    list.append(QSharedPointer<IntegerGroup>(IntegerGroup::Production2048Fixed()));

    for(int i=0; i<list.count(); i++) {
      AbstractGroup_Basic(list[i]);
    }
  }

  TEST(IntegerGroup, IsElement)
  {
    AbstractGroup_Basic(IntegerGroup::TestingFixed());
  }

  TEST(IntegerGroup, RandomExponent)
  {
    AbstractGroup_RandomExponent(IntegerGroup::TestingFixed());
  }

  TEST(IntegerGroup, NotElement) 
  {
    QSharedPointer<IntegerGroup> group = IntegerGroup::TestingFixed();

    int count = 0;
    for(int i=0; i<100; i++) {
      Element e(new IntegerElementData(Integer::GetRandomInteger(0, group->GetModulus())));
      if(group->IsElement(e)) count++;
    }

    EXPECT_TRUE(count > 30 && count < 70);
  }

  TEST(IntegerGroup, Serialize)
  {
    AbstractGroup_Serialize(IntegerGroup::TestingFixed());
  }

  TEST(IntegerGroup, Encode)
  {
    AbstractGroup_Encode(IntegerGroup::TestingFixed());
  }

}
}
