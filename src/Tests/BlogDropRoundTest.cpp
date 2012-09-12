#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "BulkRoundHelpers.hpp"
#include "ShuffleRoundHelpers.hpp"

namespace Dissent {
namespace Tests {

  TEST(BlogDropRound, BasicManaged)
  {
    RoundTest_Basic(SessionCreator(TCreateRound<BlogDropRound>),
        Group::ManagedSubgroup);
  }

  TEST(BlogDropRound, MultiRoundManaged)
  {
    RoundTest_MultiRound(SessionCreator(TCreateRound<BlogDropRound>),
        Group::ManagedSubgroup);
  }

  TEST(BlogDropRound, AddOne)
  {
    RoundTest_AddOne(SessionCreator(TCreateRound<BlogDropRound>),
        Group::ManagedSubgroup);
  }

  TEST(BlogDropRound, PeerDisconnectMiddleManaged)
  {
    RoundTest_PeerDisconnectMiddle(SessionCreator(TCreateRound<BlogDropRound>),
        Group::ManagedSubgroup);
  }

  TEST(BlogDropRound, PeerTransientIssueMiddle)
  {
    RoundTest_PeerDisconnectMiddle(SessionCreator(TCreateRound<BlogDropRound>),
        Group::ManagedSubgroup);
  }
}
}
