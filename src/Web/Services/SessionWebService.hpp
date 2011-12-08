#ifndef DISSENT_WEB_SERVICES_SESSION_WEB_SERVICE_GUARD
#define DISSENT_WEB_SERVICES_SESSION_WEB_SERVICE_GUARD

#include <QSharedPointer>

#include "../../Anonymity/Session.hpp"

#include "WebService.hpp"

namespace Dissent {
namespace Web {
namespace Services {
  /**
   * A WebService that has access to the anonymity Session object
   */
  class SessionWebService : public WebService {
    public:
      typedef Dissent::Anonymity::Session Session;

      SessionWebService(QSharedPointer<Session> session) : _session(session) {}
      virtual ~SessionWebService() {}

    protected:
      /**
       * Return the monitored session
       */
      QSharedPointer<Session> GetSession() { return _session; }

    private:
      QSharedPointer<Session> _session;
  };
}
}
}

#endif
