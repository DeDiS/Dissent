#include "DissentTest.hpp"
#include "TestNode.hpp"
#include "RoundTest.hpp"

namespace Dissent {
namespace Tests {
  void RoundTest_Null(CreateSessionCallback callback, CreateGroupGenerator cgg)
  {
    Timer::GetInstance().UseVirtualTime();
    int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    int leader = Random::GetInstance().GetInt(0, count);

    QVector<TestNode *> nodes;
    Group *group;
    ConstructOverlay(count, nodes, group);


    for(int idx = 0; idx < count; idx++) {
      for(int jdx = 0; jdx < count; jdx++) {
        if(idx == jdx) {
          continue;
        }
        EXPECT_TRUE(nodes[idx]->cm.GetConnectionTable().GetConnection(nodes[jdx]->cm.GetId()));
      }
    }

    for(int idx = 0; idx < count; idx++) {
      EXPECT_TRUE(nodes[idx]->sink.Count() == 0);
    }

    Id leader_id = nodes[leader]->cm.GetId();
    Id session_id;

    CreateSessions(nodes, *group, leader_id, session_id, callback, cgg);

    for(int idx = 0; idx < count; idx++) {
      nodes[idx]->session->Start();
    }

    TestNode::calledback = TestNode::failure = TestNode::success = 0;
    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && TestNode::calledback < count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    for(int idx = 0; idx < count; idx++) {
      EXPECT_TRUE(nodes[idx]->sink.Count() == 0);
    }

    EXPECT_EQ(TestNode::success, count);
    EXPECT_EQ(TestNode::failure, 0);

    CleanUp(nodes);
    delete group;
  }

  void RoundTest_Basic(CreateSessionCallback callback, CreateGroupGenerator cgg)
  {
    Timer::GetInstance().UseVirtualTime();

    int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    int leader = Random::GetInstance().GetInt(0, count);
    int sender = Random::GetInstance().GetInt(0, count);

    QVector<TestNode *> nodes;
    Group *group;
    ConstructOverlay(count, nodes, group);

    for(int idx = 0; idx < count; idx++) {
      for(int jdx = 0; jdx < count; jdx++) {
        if(idx == jdx) {
          continue;
        }
        EXPECT_TRUE(nodes[idx]->cm.GetConnectionTable().GetConnection(nodes[jdx]->cm.GetId()));
      }
    }

    for(int idx = 0; idx < count; idx++) {
      EXPECT_TRUE(nodes[idx]->sink.Count() == 0);
    }

    Id leader_id = nodes[leader]->cm.GetId();
    Id session_id;

    CreateSessions(nodes, *group, leader_id, session_id, callback, cgg);

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    QByteArray msg(512, 0);
    rand->GenerateBlock(msg);
    nodes[sender]->session->Send(msg);

    SignalCounter sc;
    for(int idx = 0; idx < count; idx++) {
      QObject::connect(&nodes[idx]->sink, SIGNAL(DataReceived()), &sc, SLOT(Counter()));
      nodes[idx]->session->Start();
    }

    TestNode::calledback = 0;
    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && sc.GetCount() < count && TestNode::calledback < count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    for(int idx = 0; idx < count; idx++) {
      EXPECT_EQ(msg, nodes[idx]->sink.Last().first);
    }

    CleanUp(nodes);
    delete group;
  }

  /**
   * This is a RoundTest that sets up a round and then has each
   * node make a callback to a function that takes a Session pointer
   * as an argument. This is useful for booting up a node and then
   * using it to testi SessionWebService objects.
   */
  void RoundTest_Basic_SessionTest(CreateSessionCallback callback, CreateGroupGenerator cgg,
        SessionTestCallback session_cb)
  {
    Timer::GetInstance().UseVirtualTime();

    int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    int leader = Random::GetInstance().GetInt(0, count);
    int sender = Random::GetInstance().GetInt(0, count);

    QVector<TestNode *> nodes;
    Group *group;
    ConstructOverlay(count, nodes, group);

    for(int idx = 0; idx < count; idx++) {
      for(int jdx = 0; jdx < count; jdx++) {
        if(idx == jdx) {
          continue;
        }
        EXPECT_TRUE(nodes[idx]->cm.GetConnectionTable().GetConnection(nodes[jdx]->cm.GetId()));
      }
    }

    for(int idx = 0; idx < count; idx++) {
      EXPECT_TRUE(nodes[idx]->sink.Count() == 0);
    }

    Id leader_id = nodes[leader]->cm.GetId();
    Id session_id;

    CreateSessions(nodes, *group, leader_id, session_id, callback, cgg);

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    QByteArray msg(512, 0);
    rand->GenerateBlock(msg);
    nodes[sender]->session->Send(msg);

    SignalCounter sc;
    for(int idx = 0; idx < count; idx++) {
      QObject::connect(&nodes[idx]->sink, SIGNAL(DataReceived()), &sc, SLOT(Counter()));
      nodes[idx]->session->Start();
    }

    TestNode::calledback = 0;
    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && sc.GetCount() < count && TestNode::calledback < count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    for(int idx = 0; idx < count; idx++) {
      EXPECT_EQ(msg, nodes[idx]->sink.Last().first);
    }

    for(int idx = 0; idx < count; idx++) {
      QSharedPointer<Session> sessionp(nodes[idx]->session);
      session_cb(sessionp);
    }

    CleanUp(nodes);
    delete group;
  }

  void RoundTest_MultiRound(CreateSessionCallback callback, CreateGroupGenerator cgg)
  {
    Timer::GetInstance().UseVirtualTime();

    int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    int leader = Random::GetInstance().GetInt(0, count);
    int sender0 = Random::GetInstance().GetInt(0, count);
    int sender1 = Random::GetInstance().GetInt(0, count);
    while(sender0 != sender1) {
      sender1 = Random::GetInstance().GetInt(0, count);
    }

    QVector<TestNode *> nodes;
    Group *group;
    ConstructOverlay(count, nodes, group);

    Id leader_id = nodes[leader]->cm.GetId();
    Id session_id;

    CreateSessions(nodes, *group, leader_id, session_id, callback, cgg);

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    QByteArray msg(512, 0);
    rand->GenerateBlock(msg);
    nodes[sender0]->session->Send(msg);

    SignalCounter sc;
    for(int idx = 0; idx < count; idx++) {
      QObject::connect(&nodes[idx]->sink, SIGNAL(DataReceived()), &sc, SLOT(Counter()));
      nodes[idx]->session->Start();
    }

    TestNode::calledback = 0;
    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && sc.GetCount() < count && TestNode::calledback < count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    sc.Reset();

    for(int idx = 0; idx < count; idx++) {
      EXPECT_EQ(msg, nodes[idx]->sink.Last().first);
    }

    rand->GenerateBlock(msg);
    nodes[sender1]->session->Send(msg);

    TestNode::calledback = 0;
    next = Timer::GetInstance().VirtualRun();
    while(next != -1 && sc.GetCount() < count && TestNode::calledback < count * 2) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    for(int idx = 0; idx < count; idx++) {
      EXPECT_EQ(msg, nodes[idx]->sink.Last().first);
    }

    CleanUp(nodes);
    delete group;
  }

  void RoundTest_PeerDisconnectEnd(CreateSessionCallback callback,
      CreateGroupGenerator cgg)
  {
    Timer::GetInstance().UseVirtualTime();

    int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    int leader = Random::GetInstance().GetInt(0, count);
    int disconnecter = Random::GetInstance().GetInt(0, count);
    while(leader != disconnecter) {
      disconnecter = Random::GetInstance().GetInt(0, count);
    }

    QVector<TestNode *> nodes;
    Group *group;
    ConstructOverlay(count, nodes, group);

    Id leader_id = nodes[leader]->cm.GetId();
    Id session_id;

    CreateSessions(nodes, *group, leader_id, session_id, callback, cgg);

    for(int idx = 0; idx < count; idx++) {
      nodes[idx]->session->Start();
    }

    TestNode::calledback = 0;
    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && TestNode::calledback < count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    nodes[disconnecter]->session->Stop();
    nodes[disconnecter]->cm.Disconnect();
    EXPECT_TRUE(nodes[disconnecter]->session->Stopped());

    TestNode::calledback = 0;
    next = Timer::GetInstance().VirtualRun();
    while(next != -1 && TestNode::calledback < count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    QByteArray msg(512, 0);
    rand->GenerateBlock(msg);
    nodes[(leader + disconnecter) % count]->session->Send(msg);

    TestNode::calledback = 0;
    next = Timer::GetInstance().VirtualRun();
    while(next != -1 && TestNode::calledback < count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    for(int idx = 0; idx < count; idx++) {
      EXPECT_TRUE(nodes[idx]->sink.Count() == 0);
      EXPECT_TRUE(nodes[idx]->session->Stopped());
    }

    delete nodes[disconnecter];
    nodes.remove(disconnecter);
    CleanUp(nodes);
    delete group;
  }

  void RoundTest_PeerDisconnectMiddle(CreateSessionCallback callback,
      CreateGroupGenerator cgg)
  {
    Timer::GetInstance().UseVirtualTime();

    int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    int leader = Random::GetInstance().GetInt(0, count);
    int sender = Random::GetInstance().GetInt(0, count);
    int disconnecter = Random::GetInstance().GetInt(0, count);

    QVector<TestNode *> nodes;
    Group *group;
    ConstructOverlay(count, nodes, group);

    for(int idx = 0; idx < count; idx++) {
      for(int jdx = 0; jdx < count; jdx++) {
        if(idx == jdx) {
          continue;
        }
        EXPECT_TRUE(nodes[idx]->cm.GetConnectionTable().GetConnection(nodes[jdx]->cm.GetId()));
      }
    }

    for(int idx = 0; idx < count; idx++) {
      EXPECT_TRUE(nodes[idx]->sink.Count() == 0);
    }

    Id leader_id = nodes[leader]->cm.GetId();
    Id session_id;

    CreateSessions(nodes, *group, leader_id, session_id, callback, cgg);

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    QByteArray msg(512, 0);
    rand->GenerateBlock(msg);
    nodes[sender]->session->Send(msg);

    for(int idx = 0; idx < count; idx++) {
      nodes[idx]->session->Start();
    }

    TestNode::calledback = 0;
    qint64 next = Timer::GetInstance().VirtualRun();
    // XXX This needs to be improved, but what we are doing is issuing a
    // disconnect approximately 1 to count steps into the Round
    qint64 run_before_disc = Time::GetInstance().MSecsSinceEpoch() + 
      Random::GetInstance().GetInt(10, 10 * count);

    while(next != -1 && TestNode::calledback < count && 
        Time::GetInstance().MSecsSinceEpoch() < run_before_disc)
    {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    if(Time::GetInstance().MSecsSinceEpoch() >= run_before_disc) {
      nodes[disconnecter]->cm.Disconnect();
    }

    while(next != -1 && TestNode::calledback < count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    if(Time::GetInstance().MSecsSinceEpoch() < run_before_disc) {
      std::cout << "RoundTest_PeerDisconnectMiddle never caused a disconnect, "
        "consider rerunning." << std::endl;

      for(int idx = 0; idx < count; idx++) {
        EXPECT_EQ(msg, nodes[idx]->sink.Last().first);
      }
    } else {
      foreach(TestNode *node, nodes) {
        EXPECT_TRUE(node->session->Stopped());
      }
    }

    CleanUp(nodes);
    delete group;
  }

  void RoundTest_BadGuy(CreateSessionCallback good_callback,
      CreateSessionCallback bad_callback, CreateGroupGenerator cgg,
      const BadGuyCB &cb)
  {
    Timer::GetInstance().UseVirtualTime();

    int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    int leader = Random::GetInstance().GetInt(0, count);
    int sender = Random::GetInstance().GetInt(0, count);
    int badguy = Random::GetInstance().GetInt(0, count);

    QVector<TestNode *> nodes;
    Group *group;
    ConstructOverlay(count, nodes, group);

    for(int idx = 0; idx < count; idx++) {
      for(int jdx = 0; jdx < count; jdx++) {
        if(idx == jdx) {
          continue;
        }
        EXPECT_TRUE(nodes[idx]->cm.GetConnectionTable().GetConnection(nodes[jdx]->cm.GetId()));
      }
    }

    for(int idx = 0; idx < count; idx++) {
      EXPECT_TRUE(nodes[idx]->sink.Count() == 0);
    }

    Id leader_id = nodes[leader]->cm.GetId();
    Id session_id;

    CreateSessions(nodes, *group, leader_id, session_id, good_callback, cgg);

    Session *session = nodes[0]->session.data();
    if(session) {
      const Group cg = session->GetGroupGenerator().CurrentGroup();
      int badguy_sg = Random::GetInstance().GetInt(0, cg.Count());
      Id badguy_id = cg.GetId(badguy_sg);
      badguy = cg.GetIndex(badguy_id);
    }

    qDebug() << "Bad guy at" << badguy;

    CreateSession(nodes[badguy], *group, leader_id, session_id, bad_callback, cgg);

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    QByteArray msg(512, 0);
    rand->GenerateBlock(msg);
    nodes[sender]->session->Send(msg);

    for(int idx = 0; idx < count; idx++) {
      nodes[idx]->session->Start();
    }

    TestNode::calledback = 0;
    qint64 next = Timer::GetInstance().VirtualRun();
    while(next != -1 && TestNode::calledback < count) {
      Time::GetInstance().IncrementVirtualClock(next);
      next = Timer::GetInstance().VirtualRun();
    }

    if(!cb(nodes[badguy]->session->GetCurrentRound().data())) {
      std::cout << "RoundTest_BadGuy was never triggered, "
        "consider rerunning." << std::endl;
    } else {
      foreach(TestNode *node, nodes) {
        QSharedPointer<Round> pr = node->session->GetCurrentRound();
        EXPECT_EQ(pr->GetBadMembers().count(), 1);
        if(pr->GetBadMembers().count() > 0) {
          EXPECT_TRUE(pr->GetBadMembers()[0] == badguy);
        }
        EXPECT_TRUE(node->sink.Count() == 0);
      }
    }

    CleanUp(nodes);
    delete group;
  }
}
}
