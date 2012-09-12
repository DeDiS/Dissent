#ifndef DISSENT_ANONYMITY_BLOG_DROP_ROUND_H_GUARD
#define DISSENT_ANONYMITY_BLOG_DROP_ROUND_H_GUARD

#include <QMetaEnum>

#include "Crypto/BlogDrop/BlogDropAuthor.hpp"
#include "Crypto/BlogDrop/BlogDropClient.hpp"
#include "Crypto/BlogDrop/BlogDropServer.hpp"
#include "Crypto/BlogDrop/Parameters.hpp"
#include "Crypto/BlogDrop/PrivateKey.hpp"
#include "Crypto/BlogDrop/PublicKey.hpp"
#include "Crypto/BlogDrop/PublicKeySet.hpp"
#include "RoundStateMachine.hpp"
#include "BaseBulkRound.hpp"
#include "NullRound.hpp"

namespace Dissent {
namespace Utils {
  class Random;
}

namespace Anonymity {
  class BlogDropRound : public BaseBulkRound
  {
    Q_OBJECT
    Q_ENUMS(States);
    Q_ENUMS(MessageType);

    public:
      friend class RoundStateMachine<BlogDropRound>;

      typedef Crypto::BlogDrop::BlogDropAuthor BlogDropAuthor;
      typedef Crypto::BlogDrop::BlogDropClient BlogDropClient;
      typedef Crypto::BlogDrop::BlogDropServer BlogDropServer;
      typedef Crypto::BlogDrop::Parameters Parameters;
      typedef Crypto::BlogDrop::PrivateKey PrivateKey;
      typedef Crypto::BlogDrop::PublicKey PublicKey;
      typedef Crypto::BlogDrop::PublicKeySet PublicKeySet;

      enum MessageType {
        CLIENT_PUBLIC_KEY = 0,
        SERVER_PUBLIC_KEY,
        CLIENT_MASTER_PUBLIC_KEY,
        SERVER_MASTER_PUBLIC_KEY,
        CLIENT_CIPHERTEXT,
        SERVER_CLIENT_LIST,
        SERVER_CIPHERTEXT,
        SERVER_VALIDATION,
        SERVER_CLEARTEXT,
      };

      enum States {
        OFFLINE = 0,
        SHUFFLING,
        PROCESS_DATA_SHUFFLE,
        SERVER_WAIT_FOR_CLIENT_PUBLIC_KEYS,
        WAIT_FOR_SERVER_PUBLIC_KEYS,
        SERVER_WAIT_FOR_CLIENT_MASTER_PUBLIC_KEYS,
        WAIT_FOR_SERVER_MASTER_PUBLIC_KEYS,
        PREPARE_FOR_BULK,
        CLIENT_WAIT_FOR_CLEARTEXT,
        SERVER_WAIT_FOR_CLIENT_CIPHERTEXT,
        SERVER_WAIT_FOR_CLIENT_LISTS,
        SERVER_WAIT_FOR_SERVER_CIPHERTEXT,
        SERVER_WAIT_FOR_SERVER_VALIDATION,
        SERVER_PUSH_CLEARTEXT,
        FINISHED,
      };

      /**
       * Constructor
       * @param group Group used during this round
       * @param ident the local nodes credentials
       * @param round_id Unique round id (nonce)
       * @param network handles message sending
       * @param get_data requests data to share during this session
       * @param create_shuffle optional parameter specifying a shuffle round
       * to create, currently used for testing
       */
      explicit BlogDropRound(const Group &group, const PrivateIdentity &ident,
          const Id &round_id, QSharedPointer<Network> network,
          GetDataCallback &get_data,
          CreateRound create_shuffle = &TCreateRound<NullRound>);

      /**
       * Destructor
       */
      virtual ~BlogDropRound();

      /**
       * Returns true if the local node is a member of the subgroup
       */
      inline bool IsServer() const
      {
        return GetGroup().GetSubgroup().Contains(GetLocalId());
      }

      /**
       * Converts a MessageType into a QString
       * @param mt value to convert
       */
      static QString StateToString(int state)
      {
        int index = staticMetaObject.indexOfEnumerator("States");
        return staticMetaObject.enumerator(index).valueToKey(state);
      }

      /**
       * Converts a MessageType into a QString
       * @param mt value to convert
       */
      static QString MessageTypeToString(int mtype)
      {
        int index = staticMetaObject.indexOfEnumerator("MessageType");
        return staticMetaObject.enumerator(index).valueToKey(mtype);
      }

      /**
       * Returns the string representation of the round
       */
      inline virtual QString ToString() const
      {
        return "BlogDropRound: " + GetRoundId().ToString() +
          " Phase: " + QString::number(_state_machine.GetPhase());
      }

      /**
       * Notifies this round that a peer has joined the session.  This will
       * cause this type of round to finished immediately.
       */
      virtual void PeerJoined() { _stop_next = true; }

      virtual void HandleDisconnect(const Id &id);

      inline bool UsesHashingGenerator() const
      { 
        return (_state->params->GetProofType() == Parameters::ProofType_HashingGenerator);
      }


    protected:
      typedef Utils::Random Random;

      /**
       * Funnels data into the RoundStateMachine for evaluation
       * @param data Incoming data
       * @param from the remote peer sending the data
       */
      inline virtual void ProcessData(const Id &from, const QByteArray &data)
      {
        _state_machine.ProcessData(from, data);
      }

      /**
       * Called when the BulkRound is started
       */
      virtual void OnStart();

      /**
       * Called when the BulkRound is stopped
       */
      virtual void OnStop();

      /**
       * Server sends a message to all servers
       * @param data the message to send
       */
      void VerifiableBroadcastToServers(const QByteArray &data);

      /**
       * Server sends a message to all clients
       * @param data the message to send
       */
      void VerifiableBroadcastToClients(const QByteArray &data);

    private:
      /**
       * Holds the internal state for this round
       */
      class State {
        public:
          State(QByteArray /*round_nonce*/) : 
            params(Parameters::IntegerHashingTestingFixed()),
            client_sk(new PrivateKey(params)),
            client_pk(new PublicKey(client_sk)),
            anonymous_sk(new PrivateKey(params)),
            anonymous_pk(new PublicKey(anonymous_sk)) {}

          virtual ~State() {}

          const QSharedPointer<const Parameters> params;

          /* My blogdrop preliminary keys */
          const QSharedPointer<const PrivateKey> client_sk;
          const QSharedPointer<const PublicKey> client_pk;

          /* Preliminary blogdrop keys */
          QHash<int, QSharedPointer<const PublicKey> > server_pks;
          QHash<Id, QSharedPointer<const PublicKey> > client_pks;

          /* Master blogdrop keys */
          QSharedPointer<const PrivateKey> master_client_sk;
          QSharedPointer<const PublicKey> master_client_pk;
    
          /* matrix[server_idx][client_idx] = commit */
          QHash<int, QList<QSharedPointer<const PublicKey> > > commit_matrix_servers;
          /* matrix[client_idx][client_idx] = commit */
          QHash<int, QList<QSharedPointer<const PublicKey> > > commit_matrix_clients;

          QHash<int, QSharedPointer<const PublicKey> > master_server_pks;
          QSharedPointer<const PublicKeySet> master_server_pk_set;
          QHash<Id, QSharedPointer<const PublicKey> > master_client_pks;

          /* Anon author PKs */
          const QSharedPointer<const PrivateKey> anonymous_sk;
          const QSharedPointer<const PublicKey> anonymous_pk;
          QList<QSharedPointer<const PublicKey> > slot_pks;

          /* Blogdrop ciphertext generators */
          QSharedPointer<BlogDropAuthor> blogdrop_author;
          QList<QSharedPointer<BlogDropClient> > blogdrop_clients;

          /* Plaintext output */
          QByteArray cleartext;

          QByteArray shuffle_data;

          QHash<int, QByteArray> signatures;

          int my_idx;
          int phase;
          Id my_server;

          int n_clients;
          int n_servers;
      };

      /**
       * Holds the internal state for servers in this round
       */
      class ServerState : public State {
        public:
          ServerState(QByteArray round_nonce) :
            State(round_nonce),
            server_sk(new PrivateKey(params)),
            server_pk(new PublicKey(server_sk)) {}

          virtual ~ServerState() {}

          int expected_clients;
          QSet<Id> allowed_clients;

          /* Temporary data holding my client's public keys 
           *   packets[client_id] = (packet, signature)
           */
          QHash<Id, QPair<QByteArray, QByteArray> > client_pub_packets;
          QHash<Id, QPair<QByteArray, QByteArray> > client_master_pub_packets;

          /* Blogdrop server keys */
          QSharedPointer<const PrivateKey> server_sk;
          QSharedPointer<const PublicKey> server_pk;
          QSharedPointer<const PrivateKey> master_server_sk;
          QSharedPointer<const PublicKey> master_server_pk;

          /* Blogdrop server bins */
          QList<QSharedPointer<BlogDropServer> > blogdrop_servers;

          /* Serialized hash[id] = serialized list of serialized ciphertexts */
          QHash<Id,QByteArray> client_ciphertexts;

          QByteArray my_ciphertext;

          QSet<Id> handled_servers;
          QHash<int, QByteArray> server_ciphertexts;
      };

      /**
       * Called by the constructor to initialize the server state machine
       */
      void InitServer();

      /**
       * Called by the constructor to initialize the client state machine
       */
      void InitClient();

      /**
       * Called before each state transition
       */
      void BeforeStateTransition();

      /**
       * Called after each cycle, i.e., phase conclusion
       */
      bool CycleComplete();

      /**
       * Safety net, should never be called
       */
      void EmptyHandleMessage(const Id &, QDataStream &)
      {
        qDebug() << "Received a message into the empty handle message...";
      }
        
      /**
       * Some transitions don't require any state preparation, they are handled
       * by this
       */
      void EmptyTransitionCallback() {}

      /**
       * Submits the anonymous signing key into the shuffle
       */
      virtual QPair<QByteArray, bool> GetShuffleData(int max);

      /**
       * Called when the shuffle finishes
       */
      virtual void ShuffleFinished();

      /**
       * Server handles public key from client 
       * @param from sender of the message
       * @param stream message
       */
      void HandleClientPublicKey(const Id &from, QDataStream &stream);

      /**
       * Client handles public key from server
       * @param from sender of the message
       * @param stream message
       */
      void HandleServerPublicKey(const Id &from, QDataStream &stream);

      /**
       * Server handles public key from client 
       * @param from sender of the message
       * @param stream message
       */
      void HandleClientMasterPublicKey(const Id &from, QDataStream &stream);

      /**
       * Client handles public key from server
       * @param from sender of the message
       * @param stream message
       */
      void HandleServerMasterPublicKey(const Id &from, QDataStream &stream);

      /**
       * Server handles client ciphertext messages
       * @param from sender of the message
       * @param stream message
       */
      void HandleClientCiphertext(const Id &from, QDataStream &stream);

      /**
       * Server handles other server client list messages
       * @param from sender of the message
       * @param stream message
       */
      void HandleServerClientList(const Id &from, QDataStream &stream);

      /**
       * Server handles other server ciphertext messages
       * @param from sender of the message
       * @param stream message
       */
      void HandleServerCiphertext(const Id &from, QDataStream &stream);

      /**
       * Server handles other server validation messages
       * @param from sender of the message
       * @param stream message
       */
      void HandleServerValidation(const Id &from, QDataStream &stream);

      /**
       * Client handles server cleartext message
       * @param from sender of the message
       * @param stream message
       */
      void HandleServerCleartext(const Id &from, QDataStream &stream);

      /* Below are the state transitions */
      void StartShuffle();
      void ProcessDataShuffle();
      void ProcessKeyShuffle();
      void SubmitClientPublicKey();
      void SubmitServerPublicKey();
      void SubmitClientMasterPublicKey();
      void SubmitServerMasterPublicKey();
      void PrepareForBulk();
      void SubmitClientCiphertext();
      void SetOnlineClients();
      void SubmitClientList();
      void SubmitServerCiphertext();
      void GenerateServerCiphertext();
      QByteArray GenerateClientCiphertext();
      QByteArray GenerateServerValidation();
      void SubmitValidation();
      void PushCleartext();

      void ProcessCleartext();
      void ConcludeClientCiphertextSubmission(const int &);

      QSharedPointer<ServerState> _server_state;
      QSharedPointer<State> _state;
      RoundStateMachine<BlogDropRound> _state_machine;
      bool _stop_next;
  };
}
}

#endif
