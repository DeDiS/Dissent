#include <QCoreApplication>
#include <QDebug>

#include "../Dissent.hpp"

int main(int argc, char **argv)
{
  QCoreApplication qca(argc, argv);
  QStringList args = QCoreApplication::arguments();

  if(args.count() < 2) {
    qCritical() << "Usage:" << args[0] << "settings.conf";
    return -1;
  }

  Settings settings(args[1]);
  if(!settings.IsValid()) {
    qCritical() << settings.GetError();
    return -1;
  }

  QList<Address> local;
  foreach(QUrl url, settings.LocalEndPoints) {
    local.append(AddressFactory::GetInstance().CreateAddress(url));
  }

  QList<Address> remote;
  foreach(QUrl url, settings.RemotePeers) {
    remote.append(AddressFactory::GetInstance().CreateAddress(url));
  }

  if(settings.Multithreading) {
    CryptoFactory::GetInstance().SetThreading(CryptoFactory::MultiThreaded);
  }

  Library *lib = CryptoFactory::GetInstance().GetLibrary();

  QList<QSharedPointer<Node> > nodes;

  Id local_id;
  if(!settings.LocalId.isEmpty()) {
    local_id = Id(settings.LocalId);
  }

  QSharedPointer<AsymmetricKey> key;
  QSharedPointer<DiffieHellman> dh;

  if(settings.DemoMode) {
    QByteArray id = local_id.GetByteArray();
    key = QSharedPointer<AsymmetricKey>(lib->GeneratePrivateKey(id));
    dh = QSharedPointer<DiffieHellman>(lib->GenerateDiffieHellman(id));
  } else {
    qFatal("Only DemoMode supported at this time;");
  }

  nodes.append(QSharedPointer<Node>(new Node(Credentials(local_id, key, dh),
          local, remote, settings.GroupSize, settings.SessionType)));

  for(int idx = 1; idx < settings.LocalNodeCount; idx++) {
    Id local_id;
    local[0] = AddressFactory::GetInstance().CreateAny(local[0].GetType());

    QSharedPointer<AsymmetricKey> key;
    QSharedPointer<DiffieHellman> dh;

    if(settings.DemoMode) {
      QByteArray id = local_id.GetByteArray();
      key = QSharedPointer<AsymmetricKey>(lib->GeneratePrivateKey(id));
      dh = QSharedPointer<DiffieHellman>(lib->GenerateDiffieHellman(id));
    } else {
      qFatal("Only DemoMode supported at this time;");
    }

    nodes.append(QSharedPointer<Node>(new Node(Credentials(local_id, key, dh),
            local, remote, settings.GroupSize, settings.SessionType)));
    nodes[idx]->sink = QSharedPointer<ISink>(new DummySink());
  }

  foreach(QSharedPointer<Node> node, nodes) {
    QObject::connect(&qca, SIGNAL(aboutToQuit()), &node.data()->bg, SLOT(Stop()));
    node->bg.Start();
  }

  QScopedPointer<WebServer> ws;

  if(settings.Console) {
    QSharedPointer<CommandLine> cl(new CommandLine(nodes));
    QObject::connect(nodes[0].data(), SIGNAL(Ready()), cl.data(), SLOT(Ready()));
    nodes[0]->sink = cl;
    cl->Start();
    QObject::connect(&qca, SIGNAL(aboutToQuit()), cl.data(), SLOT(Stop()));
  } else if(settings.WebServer) {
    ws.reset(new WebServer(settings.WebServerUrl));
    QObject::connect(nodes[0].data(), SIGNAL(Ready()), ws.data(), SLOT(Ready()));

    /* Stop Web server when application is about to quit */
    QObject::connect(&qca, SIGNAL(aboutToQuit()), ws.data(), SLOT(Stop()));

    /* When the web server stops, quit the application */
    QObject::connect(ws.data(), SIGNAL(Stopped()), &qca, SLOT(quit()));

    QSharedPointer<Dissent::Messaging::SignalSink> signal_sink(new Dissent::Messaging::SignalSink());
    nodes[0]->sink = signal_sink;

    QSharedPointer<GetMessagesService> get_messages_sp(new GetMessagesService());
    QObject::connect(signal_sink.data(), SIGNAL(IncomingData(const QByteArray&)),
        get_messages_sp.data(), SLOT(HandleIncomingMessage(const QByteArray&)));
    ws->AddRoute(HttpRequest::METHOD_HTTP_GET, "/session/messages/all", get_messages_sp);

    QSharedPointer<GetNextMessageService> get_next_message_sp(new GetNextMessageService());
    QObject::connect(signal_sink.data(), SIGNAL(IncomingData(const QByteArray&)),
        get_next_message_sp.data(), SLOT(HandleIncomingMessage(const QByteArray&)));
    ws->AddRoute(HttpRequest::METHOD_HTTP_GET, "/session/messages/next", get_next_message_sp);

    QSharedPointer<RoundIdService> round_id_sp(new RoundIdService(nodes[0]));
    ws->AddRoute(HttpRequest::METHOD_HTTP_GET, "/round/id", round_id_sp);

    QSharedPointer<SessionIdService> session_id_sp(new SessionIdService(nodes[0]));
    ws->AddRoute(HttpRequest::METHOD_HTTP_GET, "/session/id", session_id_sp);

    QSharedPointer<SendMessageService> send_message_sp(new SendMessageService(nodes[0]));
    ws->AddRoute(HttpRequest::METHOD_HTTP_POST, "/session/send", send_message_sp);

    ws->Start();
  } else {
    nodes[0]->sink = QSharedPointer<ISink>(new DummySink());
  }

  return QCoreApplication::exec();
}
