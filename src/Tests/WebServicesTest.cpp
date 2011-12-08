#include <QByteArray>
#include <QDebug>
#include <QList>
#include <QMap>
#include <QTextStream>
#include <QVariant>

#include "Web/WebRequest.hpp"
#include "Web/Services/GetMessagesService.hpp"
#include "Web/Services/GetNextMessageService.hpp"
#include "Web/Services/RoundIdService.hpp"
#include "Web/Services/SendMessageService.hpp"
#include "Web/Services/SessionIdService.hpp"

#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "ShuffleRoundHelpers.hpp"

#include "WebServicesTest.hpp"

namespace Dissent {
namespace Tests {

  namespace {
    using namespace Dissent::Web;
    using namespace Dissent::Web::Services;
  }

  void WebServiceTestSink::HandleDoneRequest(QSharedPointer<WebRequest> wrp)
  {
    handled.append(wrp);
  }

  QSharedPointer<WebRequest> FakeRequest()
  {
    QTcpSocket *socketp = new QTcpSocket();
    QSharedPointer<WebRequest> wrp(new WebRequest(socketp));
    return wrp;
  }

  TEST(WebServices, GetMessagesService)
  {
    WebServiceTestSink sink;
    GetMessagesService gsm;
    QObject::connect(&gsm, SIGNAL(FinishedWebRequest(QSharedPointer<WebRequest>)),
       &sink, SLOT(HandleDoneRequest(QSharedPointer<WebRequest>)));

    QByteArray data1, data2;
    data1 = "Test 1";
    data2 = "Test 2";

    ASSERT_EQ(sink.handled.count(), 0);

    gsm.Handle(FakeRequest());
    ASSERT_EQ(sink.handled.count(), 1);
    ASSERT_EQ(HttpResponse::STATUS_OK, sink.handled[0]->GetStatus());

    gsm.HandleIncomingMessage(data1);
    ASSERT_EQ(sink.handled.count(), 1);
    
    gsm.Handle(FakeRequest());
    ASSERT_EQ(sink.handled.count(), 2);
    ASSERT_EQ(HttpResponse::STATUS_OK, sink.handled[1]->GetStatus());

    QVariant var = sink.handled[1]->GetOutputData();
    ASSERT_TRUE(var.canConvert(QVariant::List));
    QList<QVariant> list = var.toList();
    ASSERT_TRUE(list[0].canConvert(QVariant::ByteArray));
    ASSERT_EQ(data1, list[0].toByteArray());

    
    gsm.HandleIncomingMessage(data2);
    ASSERT_EQ(sink.handled.count(), 2);
    
    gsm.Handle(FakeRequest());
    ASSERT_EQ(sink.handled.count(), 3);
    ASSERT_EQ(HttpResponse::STATUS_OK, sink.handled[2]->GetStatus());

    var = sink.handled[2]->GetOutputData();
    ASSERT_TRUE(var.canConvert(QVariant::List));
    list = var.toList();
    ASSERT_TRUE(list[1].canConvert(QVariant::ByteArray));
    ASSERT_EQ(data1, list[1].toByteArray());
  }

  TEST(WebServices, GetNextMessageService)
  {
    WebServiceTestSink sink;
    GetNextMessageService gnm;
    QObject::connect(&gnm, SIGNAL(FinishedWebRequest(QSharedPointer<WebRequest>)),
       &sink, SLOT(HandleDoneRequest(QSharedPointer<WebRequest>)));

    QByteArray data1, data2;
    data1 = "Msg 1";
    data2 = "Msg 2";

    ASSERT_EQ(sink.handled.count(), 0);

    gnm.Handle(FakeRequest());
    ASSERT_EQ(sink.handled.count(), 0);

    gnm.HandleIncomingMessage(data1);
    ASSERT_EQ(sink.handled.count(), 1);
    ASSERT_EQ(HttpResponse::STATUS_OK, sink.handled[0]->GetStatus());

    QVariant var = sink.handled[0]->GetOutputData();
    ASSERT_TRUE(var.canConvert(QVariant::Map));
    QMap<QString,QVariant> map = var.toMap();
    ASSERT_TRUE(map["message"].canConvert(QVariant::ByteArray));
    ASSERT_EQ(data1, map["message"].toByteArray());

    gnm.Handle(FakeRequest());
    ASSERT_EQ(sink.handled.count(), 1);

    gnm.HandleIncomingMessage(data2);
    ASSERT_EQ(sink.handled.count(), 2);
    ASSERT_EQ(HttpResponse::STATUS_OK, sink.handled[1]->GetStatus());

    ASSERT_TRUE(var.canConvert(QVariant::Map));
    map = var.toMap();
    ASSERT_TRUE(map["message"].canConvert(QVariant::ByteArray));
    ASSERT_EQ(data1, map["message"].toByteArray());
  }

  void RoundIdServiceTest(QSharedPointer<Session> sessionp) 
  {
    ASSERT_TRUE(!sessionp.isNull());

    WebServiceTestSink sink;
    ASSERT_EQ(sink.handled.count(), 0);

    RoundIdService rid(sessionp);
    QObject::connect(&rid, SIGNAL(FinishedWebRequest(QSharedPointer<WebRequest>)),
       &sink, SLOT(HandleDoneRequest(QSharedPointer<WebRequest>)));
   
    rid.Handle(FakeRequest());
    ASSERT_EQ(sink.handled.count(), 1);
    ASSERT_EQ(HttpResponse::STATUS_OK, sink.handled[0]->GetStatus());
    
    QVariant var = sink.handled[0]->GetOutputData();
    ASSERT_TRUE(var.canConvert(QVariant::Map));
    QMap<QString,QVariant> map = var.toMap();
    ASSERT_TRUE(map["active"].canConvert(QVariant::Bool));
    ASSERT_TRUE(map["active"].toBool());
    ASSERT_TRUE(map["id"].canConvert(QVariant::String));
    ASSERT_EQ("ABC", map["id"].toString());
  }

  TEST(WebServices, RoundIdServiceActive)
  {
    RoundTest_Basic_SessionTest(&TCreateSession<ShuffleRound>, &GroupGenerator::Create,
      &RoundIdServiceTest);
  }

}
}
