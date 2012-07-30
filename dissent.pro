######################################################################
# Automatically generated by qmake (2.01a) Thu Sep 15 17:01:48 2011
######################################################################

TEMPLATE = lib
TARGET = dissent
DEPENDPATH += 
INCLUDEPATH += ext/joyent-http-parser/ ext/qt-json/ src/ ext/qxt
CONFIG += qt debug
QT = core network
DEFINES += "VERSION=3"
QMAKE_CXXFLAGS += -Werror
QMAKE_CFLAGS += -Werror

# Input
LIBS += -lcryptopp 
HEADERS += ext/joyent-http-parser/http_parser.h \
           ext/qt-json/json.h \
           ext/qxt/qxtcommandoptions.h \
           ext/qxt/qxtglobal.h \
           src/Dissent.hpp \
           src/Anonymity/BaseBulkRound.hpp \
           src/Anonymity/BulkRound.hpp \
           src/Anonymity/CSBulkRound.hpp \
           src/Anonymity/Log.hpp \
           src/Anonymity/MessageRandomizer.hpp \
           src/Anonymity/NeffKeyShuffle.hpp \
           src/Anonymity/NullRound.hpp \
           src/Anonymity/RepeatingBulkRound.hpp \
           src/Anonymity/Round.hpp \
           src/Anonymity/RoundStateMachine.hpp \
           src/Anonymity/Sessions/Session.hpp \
           src/Anonymity/Sessions/SessionLeader.hpp \
           src/Anonymity/Sessions/SessionManager.hpp \
           src/Anonymity/ShuffleBlamer.hpp \
           src/Anonymity/ShuffleRound.hpp \
           src/Anonymity/ShuffleRoundBlame.hpp \
           src/Anonymity/Tolerant/Accusation.hpp \
           src/Anonymity/Tolerant/AlibiData.hpp \
           src/Anonymity/Tolerant/BlameMatrix.hpp \
           src/Anonymity/Tolerant/Conflict.hpp \
           src/Anonymity/Tolerant/MessageHistory.hpp \
           src/Anonymity/Tolerant/TolerantBulkRound.hpp \
           src/Applications/CommandLine.hpp \
           src/Applications/ConsoleSink.hpp \
           src/Applications/FileSink.hpp \
           src/Applications/Node.hpp \
           src/Applications/SessionFactory.hpp \
           src/Applications/Settings.hpp \
           src/ClientServer/CSBroadcast.hpp \
           src/ClientServer/CSConnectionAcquirer.hpp \
           src/ClientServer/CSForwarder.hpp \
           src/ClientServer/CSNetwork.hpp \
           src/ClientServer/CSOverlay.hpp \
           src/Connections/Bootstrapper.hpp \
           src/Connections/Connection.hpp \
           src/Connections/ConnectionAcquirer.hpp \
           src/Connections/ConnectionManager.hpp \
           src/Connections/ConnectionTable.hpp \
           src/Connections/DefaultNetwork.hpp \
           src/Connections/EmptyNetwork.hpp \
           src/Connections/ForwardingSender.hpp \
           src/Connections/FullyConnected.hpp \
           src/Connections/Id.hpp \
           src/Connections/IOverlaySender.hpp \
           src/Connections/Network.hpp \
           src/Connections/RelayAddress.hpp \
           src/Connections/RelayEdge.hpp \
           src/Connections/RelayEdgeListener.hpp \
           src/Connections/RelayForwarder.hpp \
           src/Crypto/AsymmetricKey.hpp \
           src/Crypto/CppDiffieHellman.hpp \
           src/Crypto/CppDsaPrivateKey.hpp \
           src/Crypto/CppDsaPublicKey.hpp \
           src/Crypto/CppHash.hpp \
           src/Crypto/CppIntegerData.hpp \
           src/Crypto/CppLibrary.hpp \
           src/Crypto/CppPrivateKey.hpp \
           src/Crypto/CppPublicKey.hpp \
           src/Crypto/CppRandom.hpp \
           src/Crypto/CryptoFactory.hpp \
           src/Crypto/DiffieHellman.hpp \
           src/Crypto/NullDiffieHellman.hpp \
           src/Crypto/Hash.hpp \
           src/Crypto/Integer.hpp \
           src/Crypto/IntegerData.hpp \
           src/Crypto/LRSPrivateKey.hpp \
           src/Crypto/LRSPublicKey.hpp \
           src/Crypto/LRSSignature.hpp \
           src/Crypto/NullHash.hpp \
           src/Crypto/NullLibrary.hpp \
           src/Crypto/NullPublicKey.hpp \
           src/Crypto/NullPrivateKey.hpp \
           src/Crypto/Library.hpp \
           src/Crypto/OnionEncryptor.hpp \
           src/Crypto/ThreadedOnionEncryptor.hpp \
           src/Crypto/Serialization.hpp \
           src/Crypto/BlogDrop/ClientCiphertext.hpp \
           src/Crypto/BlogDrop/Parameters.hpp \
           src/Crypto/BlogDrop/Plaintext.hpp \
           src/Crypto/BlogDrop/PrivateKey.hpp \
           src/Crypto/BlogDrop/PublicKey.hpp \
           src/Crypto/BlogDrop/PublicKeySet.hpp \
           src/Crypto/BlogDrop/ServerCiphertext.hpp \
           src/Identity/Authentication/IAuthenticate.hpp \
           src/Identity/Authentication/IAuthenticator.hpp \
           src/Identity/Authentication/LRSAuthenticate.hpp \
           src/Identity/Authentication/LRSAuthenticator.hpp \
           src/Identity/Authentication/NullAuthenticate.hpp \
           src/Identity/Authentication/NullAuthenticator.hpp \
           src/Identity/Authentication/PreExchangedKeyAuthenticate.hpp \
           src/Identity/Authentication/PreExchangedKeyAuthenticator.hpp \
           src/Identity/Group.hpp \
           src/Identity/GroupHolder.hpp \
           src/Identity/PrivateIdentity.hpp \
           src/Identity/PublicIdentity.hpp \
           src/Messaging/BufferSink.hpp \
           src/Messaging/DummySink.hpp \
           src/Messaging/Filter.hpp \
           src/Messaging/FilterObject.hpp \
           src/Messaging/GetDataCallback.hpp \
           src/Messaging/ISender.hpp \
           src/Messaging/ISink.hpp \
           src/Messaging/ISinkObject.hpp \
           src/Messaging/Request.hpp \
           src/Messaging/RequestResponder.hpp \
           src/Messaging/RequestHandler.hpp \
           src/Messaging/Response.hpp \
           src/Messaging/ResponseHandler.hpp \
           src/Messaging/RpcHandler.hpp \
           src/Messaging/SignalSink.hpp \
           src/Messaging/Source.hpp \
           src/Messaging/SourceObject.hpp \
           src/Overlay/BaseOverlay.hpp \
           src/Overlay/BasicGossip.hpp \
           src/PeerReview/Acknowledgement.hpp \
           src/PeerReview/AcknowledgementLog.hpp \
           src/PeerReview/Entry.hpp \
           src/PeerReview/EntryParser.hpp \
           src/PeerReview/EntryLog.hpp \
           src/PeerReview/SendEntry.hpp \
           src/PeerReview/PRManager.hpp \
           src/PeerReview/ReceiveEntry.hpp \
           src/Transports/Address.hpp \
           src/Transports/AddressFactory.hpp \
           src/Transports/BufferAddress.hpp \
           src/Transports/BufferEdge.hpp \
           src/Transports/BufferEdgeListener.hpp \
           src/Transports/Edge.hpp \
           src/Transports/EdgeFactory.hpp \
           src/Transports/EdgeListener.hpp \
           src/Transports/EdgeListenerFactory.hpp \
           src/Transports/TcpAddress.hpp \
           src/Transports/TcpEdge.hpp \
           src/Transports/TcpEdgeListener.hpp \
           src/Tunnel/EntryTunnel.hpp \
           src/Tunnel/ExitTunnel.hpp \
           src/Tunnel/SocksConnection.hpp \
           src/Tunnel/SocksHostAddress.hpp \
           src/Tunnel/TunnelConnectionTable.hpp \
           src/Tunnel/Packets/Packet.hpp \
           src/Tunnel/Packets/FinishPacket.hpp \
           src/Tunnel/Packets/TcpRequestPacket.hpp \
           src/Tunnel/Packets/UdpRequestPacket.hpp \
           src/Tunnel/Packets/TcpResponsePacket.hpp \
           src/Tunnel/Packets/UdpResponsePacket.hpp \
           src/Tunnel/Packets/TcpStartPacket.hpp \
           src/Tunnel/Packets/UdpStartPacket.hpp \
           src/Utils/Logging.hpp \
           src/Utils/Random.hpp \
           src/Utils/QRunTimeError.hpp \
           src/Utils/Serialization.hpp \
           src/Utils/SignalCounter.hpp \
           src/Utils/Sleeper.hpp \
           src/Utils/StartStop.hpp \
           src/Utils/StartStopSlots.hpp \
           src/Utils/Time.hpp \
           src/Utils/Timer.hpp \
           src/Utils/TimerCallback.hpp \
           src/Utils/TimerEvent.hpp \
           src/Utils/Triggerable.hpp \
           src/Utils/Triple.hpp \
           src/Utils/Utils.hpp \
           src/Web/HttpRequest.hpp \
           src/Web/HttpResponse.hpp \
           src/Web/WebRequest.hpp \
           src/Web/WebServer.hpp \
           src/Web/Packagers/Packager.hpp \
           src/Web/Packagers/JsonPackager.hpp \
           src/Web/Services/GetFileService.hpp \
           src/Web/Services/GetMessagesService.hpp \
           src/Web/Services/MessageWebService.hpp \
           src/Web/Services/RoundIdService.hpp \
           src/Web/Services/SendMessageService.hpp \
           src/Web/Services/SessionIdService.hpp \
           src/Web/Services/SessionWebService.hpp \
           src/Web/Services/WebService.hpp 

SOURCES += ext/joyent-http-parser/http_parser.c \
           ext/qt-json/json.cpp \
           ext/qxt/qxtcommandoptions.cpp \
           src/Anonymity/BaseBulkRound.cpp \
           src/Anonymity/BulkRound.cpp \
           src/Anonymity/CSBulkRound.cpp \
           src/Anonymity/Log.cpp \
           src/Anonymity/MessageRandomizer.cpp \
           src/Anonymity/NeffKeyShuffle.cpp \
           src/Anonymity/NullRound.cpp \
           src/Anonymity/RepeatingBulkRound.cpp \
           src/Anonymity/Round.cpp \
           src/Anonymity/Sessions/Session.cpp \
           src/Anonymity/Sessions/SessionLeader.cpp \
           src/Anonymity/Sessions/SessionManager.cpp \
           src/Anonymity/ShuffleBlamer.cpp \
           src/Anonymity/ShuffleRound.cpp \
           src/Anonymity/ShuffleRoundBlame.cpp \
           src/Anonymity/Tolerant/Accusation.cpp \
           src/Anonymity/Tolerant/AlibiData.cpp \
           src/Anonymity/Tolerant/BlameMatrix.cpp \
           src/Anonymity/Tolerant/MessageHistory.cpp \
           src/Anonymity/Tolerant/TolerantBulkRound.cpp \
           src/Applications/CommandLine.cpp \
           src/Applications/ConsoleSink.cpp \
           src/Applications/FileSink.cpp \
           src/Applications/Node.cpp \
           src/Applications/SessionFactory.cpp \
           src/Applications/Settings.cpp \
           src/ClientServer/CSBroadcast.cpp \
           src/ClientServer/CSConnectionAcquirer.cpp \
           src/ClientServer/CSForwarder.cpp \
           src/ClientServer/CSNetwork.cpp \
           src/ClientServer/CSOverlay.cpp \
           src/Connections/Bootstrapper.cpp \
           src/Connections/Connection.cpp \
           src/Connections/ConnectionManager.cpp \
           src/Connections/ConnectionTable.cpp \
           src/Connections/FullyConnected.cpp \
           src/Connections/Id.cpp \
           src/Connections/RelayAddress.cpp \
           src/Connections/RelayEdge.cpp \
           src/Connections/RelayEdgeListener.cpp \
           src/Connections/RelayForwarder.cpp \
           src/Crypto/AsymmetricKey.cpp \
           src/Crypto/CppDiffieHellman.cpp \
           src/Crypto/CppDsaPrivateKey.cpp \
           src/Crypto/CppDsaPublicKey.cpp \
           src/Crypto/CppHash.cpp \
           src/Crypto/CppPrivateKey.cpp \
           src/Crypto/CppPublicKey.cpp \
           src/Crypto/CppRandom.cpp \
           src/Crypto/CryptoFactory.cpp \
           src/Crypto/DiffieHellman.cpp \
           src/Crypto/LRSPrivateKey.cpp \
           src/Crypto/LRSPublicKey.cpp \
           src/Crypto/NullDiffieHellman.cpp \
           src/Crypto/NullHash.cpp \
           src/Crypto/NullPublicKey.cpp \
           src/Crypto/NullPrivateKey.cpp \
           src/Crypto/OnionEncryptor.cpp \
           src/Crypto/ThreadedOnionEncryptor.cpp \
           src/Crypto/BlogDrop/ClientCiphertext.cpp \
           src/Crypto/BlogDrop/Parameters.cpp \
           src/Crypto/BlogDrop/Plaintext.cpp \
           src/Crypto/BlogDrop/PrivateKey.cpp \
           src/Crypto/BlogDrop/PublicKey.cpp \
           src/Crypto/BlogDrop/PublicKeySet.cpp \
           src/Crypto/BlogDrop/ServerCiphertext.cpp \
           src/Identity/Group.cpp \
           src/Identity/Authentication/LRSAuthenticate.cpp \
           src/Identity/Authentication/LRSAuthenticator.cpp \
           src/Identity/Authentication/PreExchangedKeyAuthenticate.cpp \
           src/Identity/Authentication/PreExchangedKeyAuthenticator.cpp \
           src/Messaging/RpcHandler.cpp \
           src/Messaging/SignalSink.cpp \
           src/Overlay/BaseOverlay.cpp \
           src/Overlay/BasicGossip.cpp \
           src/PeerReview/AcknowledgementLog.cpp \
           src/PeerReview/Entry.cpp \
           src/PeerReview/EntryLog.cpp \
           src/PeerReview/EntryParser.cpp \
           src/PeerReview/PRManager.cpp \
           src/Transports/Address.cpp \
           src/Transports/AddressFactory.cpp \
           src/Transports/BufferAddress.cpp \
           src/Transports/BufferEdge.cpp \
           src/Transports/BufferEdgeListener.cpp \
           src/Transports/Edge.cpp \
           src/Transports/EdgeFactory.cpp \
           src/Transports/EdgeListener.cpp \
           src/Transports/EdgeListenerFactory.cpp \
           src/Transports/TcpAddress.cpp \
           src/Transports/TcpEdge.cpp \
           src/Transports/TcpEdgeListener.cpp \
           src/Tunnel/EntryTunnel.cpp \
           src/Tunnel/ExitTunnel.cpp \
           src/Tunnel/SocksConnection.cpp \
           src/Tunnel/SocksHostAddress.cpp \
           src/Tunnel/TunnelConnectionTable.cpp \
           src/Tunnel/Packets/Packet.cpp \
           src/Tunnel/Packets/FinishPacket.cpp \
           src/Tunnel/Packets/TcpRequestPacket.cpp \
           src/Tunnel/Packets/UdpRequestPacket.cpp \
           src/Tunnel/Packets/TcpResponsePacket.cpp \
           src/Tunnel/Packets/UdpResponsePacket.cpp \
           src/Tunnel/Packets/TcpStartPacket.cpp \
           src/Tunnel/Packets/UdpStartPacket.cpp \
           src/Utils/Logging.cpp \
           src/Utils/Random.cpp \
           src/Utils/Sleeper.cpp \
           src/Utils/StartStop.cpp \
           src/Utils/Time.cpp \
           src/Utils/Timer.cpp \
           src/Utils/TimerEvent.cpp \
           src/Utils/Utils.cpp \
           src/Web/HttpRequest.cpp \
           src/Web/HttpResponse.cpp \
           src/Web/WebRequest.cpp \
           src/Web/WebServer.cpp \
           src/Web/Packagers/JsonPackager.cpp \
           src/Web/Services/GetFileService.cpp \
           src/Web/Services/GetMessagesService.cpp \
           src/Web/Services/RoundIdService.cpp \
           src/Web/Services/SendMessageService.cpp \
           src/Web/Services/SessionIdService.cpp \
           src/Web/Services/WebService.cpp
