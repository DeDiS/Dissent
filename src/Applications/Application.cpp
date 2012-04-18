#include <QCoreApplication>
#include <QDebug>

#include "Dissent.hpp"

int main(int argc, char **argv)
{
  QCoreApplication qca(argc, argv);
  QStringList args = QCoreApplication::arguments();

  if(args.count() < 2) {
    qCritical() << "Usage:" << args[0] << "[flags] settings.conf";
    return -1;
  }

  Settings settings(args);
  if(!settings.IsValid()) {
    qFatal("%s", settings.GetError().toAscii().constData());
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

  Group group(QVector<PublicIdentity>(), Id(settings.LeaderId),
      settings.SubgroupPolicy);

  QList<QSharedPointer<Node> > nodes;

  QSharedPointer<ISink> default_sink(new DummySink());
  QSharedPointer<ISink> app_sink;

  QScopedPointer<WebServer> ws;
  QScopedPointer<EntryTunnel> tun_entry;
  QScopedPointer<ExitTunnel> tun_exit;

  if(settings.Mode == Settings::Mode_Null) {
    app_sink = default_sink;
  } else if(settings.Mode == Settings::Mode_Console) {
    app_sink = QSharedPointer<CommandLine>(new CommandLine(nodes));
  } else if(settings.Mode == Settings::Mode_WebServer 
      || settings.Mode == Settings::Mode_EntryTunnel
      || settings.Mode == Settings::Mode_ExitTunnel) {
    app_sink = QSharedPointer<SignalSink>(new SignalSink());
  } else {
    qCritical() << "Unknown mode type";
  }

  Id local_id = (settings.LocalId == Id::Zero()) ? Id() : settings.LocalId;
  QSharedPointer<AsymmetricKey> key;
  QSharedPointer<DiffieHellman> dh;

  if(settings.DemoMode) {
    QByteArray id = local_id.GetByteArray();
    key = QSharedPointer<AsymmetricKey>(lib->GeneratePrivateKey(id));
    dh = QSharedPointer<DiffieHellman>(lib->GenerateDiffieHellman(id));
  } else {
    qCritical() << "Only DemoMode supported at this time;";
  }

  Node::CreateNode create = &Node::CreateBasicGossip;
  if(settings.SubgroupPolicy == Group::ManagedSubgroup) {
    create = &Node::CreateClientServer;
  }

  bool force_super_peer = local[0].GetType().compare("buffer") == 0;
  bool super_peer = settings.SuperPeer || force_super_peer;

  nodes.append(create(PrivateIdentity(local_id, key, dh, super_peer),
        group, local, remote, app_sink, settings.SessionType));

  for(int idx = 1; idx < settings.LocalNodeCount; idx++) {
    if(idx < 3) {
      super_peer = force_super_peer;
    } else {
      super_peer = settings.SuperPeer;
    }

    Id local_id;
    local[0] = AddressFactory::GetInstance().CreateAny(local[0].GetType());

    QSharedPointer<AsymmetricKey> key;
    QSharedPointer<DiffieHellman> dh;

    if(settings.DemoMode) {
      QByteArray id = local_id.GetByteArray();
      key = QSharedPointer<AsymmetricKey>(lib->GeneratePrivateKey(id));
      dh = QSharedPointer<DiffieHellman>(lib->GenerateDiffieHellman(id));
    } else {
      qCritical() << "Only DemoMode supported at this time;";
    }

    nodes.append(create(PrivateIdentity(local_id, key, dh, super_peer),
          group, local, remote, default_sink, settings.SessionType));
  }


  QSharedPointer<DefaultNetwork> net(new DefaultNetwork(nodes[0]->GetOverlay()->GetConnectionManager(), 
        nodes[0]->GetOverlay()->GetRpcHandler()));
  if(settings.Mode == Settings::Mode_Console) {
    QSharedPointer<CommandLine> cl = app_sink.dynamicCast<CommandLine>();
    if(!cl) qCritical() << "Could not cast QSharedPointer";

    QObject::connect(&qca, SIGNAL(aboutToQuit()), cl.data(), SLOT(Stop()));
    cl->Start();
  } else if(settings.Mode == Settings::Mode_WebServer) {
    ws.reset(new WebServer(settings.WebServerUrl));

    /* Stop Web server when application is about to quit */
    QObject::connect(&qca, SIGNAL(aboutToQuit()), ws.data(), SLOT(Stop()));

    /* When the web server stops, quit the application */
    QObject::connect(ws.data(), SIGNAL(Stopped()), &qca, SLOT(quit()));

    QSharedPointer<SignalSink> signal_sink = app_sink.dynamicCast<SignalSink>();
    if(!signal_sink) qCritical() << "Could not cast QSharedPointer";

    QSharedPointer<GetMessagesService> get_messages_sp(new GetMessagesService());
    QObject::connect(signal_sink.data(), SIGNAL(IncomingData(const QByteArray&)),
        get_messages_sp.data(), SLOT(HandleIncomingMessage(const QByteArray&)));
    ws->AddRoute(HttpRequest::METHOD_HTTP_GET, "/session/messages", get_messages_sp);

    QSharedPointer<GetFileService> get_webpage_sp(new GetFileService("index.html"));
    ws->AddRoute(HttpRequest::METHOD_HTTP_GET, "/web", get_webpage_sp);

    QSharedPointer<RoundIdService> round_id_sp(new RoundIdService(nodes[0]->GetSessionManager()));
    ws->AddRoute(HttpRequest::METHOD_HTTP_GET, "/round/id", round_id_sp);

    QSharedPointer<SessionIdService> session_id_sp(new SessionIdService(nodes[0]->GetSessionManager()));
    ws->AddRoute(HttpRequest::METHOD_HTTP_GET, "/session/id", session_id_sp);

    QSharedPointer<SendMessageService> send_message_sp(new SendMessageService(nodes[0]->GetSessionManager()));
    ws->AddRoute(HttpRequest::METHOD_HTTP_POST, "/session/send", send_message_sp);

    ws->Start();

  } else if(settings.Mode == Settings::Mode_EntryTunnel) {
    QSharedPointer<SignalSink> signal_sink = app_sink.dynamicCast<SignalSink>();
    if(!signal_sink) qCritical() <<  "Could not cast QSharedPointer";

    tun_entry.reset(new EntryTunnel(settings.EntryTunnelUrl, nodes[0]->GetSessionManager(), 
          nodes[0]->GetOverlay()->GetRpcHandler()));

    QObject::connect(signal_sink.data(), SIGNAL(IncomingData(const QByteArray&)),
        tun_entry.data(), SLOT(DownstreamData(const QByteArray&)));

    tun_entry->Start();

  } else if(settings.Mode == Settings::Mode_ExitTunnel) {
    QSharedPointer<SignalSink> signal_sink = app_sink.dynamicCast<SignalSink>();
    if(!signal_sink) qFatal("Could not cast QSharedPointer");

    tun_exit.reset(new ExitTunnel(nodes[0]->GetSessionManager(), net, settings.ExitTunnelProxyUrl)); 

    QObject::connect(signal_sink.data(), SIGNAL(IncomingData(const QByteArray&)),
        tun_exit.data(), SLOT(SessionData(const QByteArray&)));

    tun_exit->Start();
  }

  foreach(QSharedPointer<Node> node, nodes) {
    QObject::connect(&qca, SIGNAL(aboutToQuit()),
        node.data()->GetOverlay().data(), SLOT(CallStop()));
    node->GetOverlay()->Start();
  }

  return QCoreApplication::exec();
}
