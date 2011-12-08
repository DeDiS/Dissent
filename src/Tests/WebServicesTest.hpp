
#include <QList>
#include <QObject>
#include <QSharedPointer>

#include "DissentTest.hpp"
#include "Web/WebRequest.hpp"

namespace Dissent {
namespace Tests {

  namespace {
    using namespace Dissent::Web;
  }

  class WebServiceTestSink : public QObject {
    Q_OBJECT

    public slots:
      void HandleDoneRequest(QSharedPointer<WebRequest> wrp);

    public:
      QList<QSharedPointer<WebRequest> > handled;

  };
}
}
