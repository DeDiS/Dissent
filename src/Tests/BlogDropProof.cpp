#include "AbstractGroupHelpers.hpp"
#include "DissentTest.hpp"
#include <cryptopp/ecp.h>
#include <cryptopp/nbtheory.h>

namespace Dissent {
namespace Tests {

  void TestElGamalServerCiphertext(QSharedPointer<const Parameters> params)
  {
    for(int t=0; t<10; t++) {
      const int nkeys = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);

      QList<QSharedPointer<const PublicKeySet> > sets;
      for(int j=0; j<params->GetNElements(); j++) {
        QList<QSharedPointer<const PublicKey> > client_pks;
        for(int i=0; i<nkeys; i++) {
          QSharedPointer<const PrivateKey> priv(new PrivateKey(params));
          QSharedPointer<const PublicKey> pub(new PublicKey(priv));
          client_pks.append(pub);
        }
        sets.append(QSharedPointer<const PublicKeySet>(new PublicKeySet(params, client_pks)));
      }

      QSharedPointer<const PrivateKey> server_sk(new PrivateKey(params));
      QSharedPointer<const PublicKey> server_pk(new PublicKey(server_sk));

      QSharedPointer<const PrivateKey> author_sk(new PrivateKey(params));
      QSharedPointer<const PublicKey> author_pk(new PublicKey(author_sk));

      EXPECT_FALSE(params.isNull());
      ElGamalServerCiphertext c(params, author_pk, sets);
      c.SetProof(0, server_sk);

      for(int j=0; j<params->GetNElements(); j++) {
        Element expected = params->GetMessageGroup()->Exponentiate(sets[j]->GetElement(), 
            server_sk->GetInteger());
        expected = params->GetMessageGroup()->Inverse(expected);
        ASSERT_EQ(params->GetNElements(), c.GetElements().count());
        ASSERT_EQ(expected, c.GetElements()[j]);
      }

      ASSERT_TRUE(c.VerifyProof(0, server_pk));
    }
  }

  TEST(BlogDropProof, CppIntegerElGamalServer) {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(CryptoFactory::CryptoPP);
    TestElGamalServerCiphertext(Parameters::Parameters::IntegerElGamalTestingFixed());
    cf.SetLibrary(cname);
  }

  TEST(BlogDrop, OpenIntegerElGamalServer) {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(CryptoFactory::OpenSSL);
    TestElGamalServerCiphertext(Parameters::Parameters::IntegerElGamalTestingFixed());
    cf.SetLibrary(cname);
  }

  TEST(BlogDropProof, CppECElGamalServer) {
    TestElGamalServerCiphertext(Parameters::Parameters::CppECElGamalProductionFixed());
  }

  TEST(BlogDropProof, OpenECElGamalServer) {
    TestElGamalServerCiphertext(Parameters::Parameters::OpenECElGamalProductionFixed());
  }

  void TestClientOnce(QSharedPointer<const Parameters> params)
  {
    // Generate an author PK
    QSharedPointer<const PrivateKey> priv(new PrivateKey(params));
    QSharedPointer<const PublicKey> author_pk(new PublicKey(priv));

    // Generate list of server pks
    const int nservers = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    QList<QSharedPointer<const PublicKey> > server_pks;
    for(int i=0; i<nservers; i++) {
      QSharedPointer<const PrivateKey> priv(new PrivateKey(params));
      QSharedPointer<const PublicKey> pub(new PublicKey(priv));
      server_pks.append(pub);
    }

    QSharedPointer<const PrivateKey> client_priv(new PrivateKey(params));
    QSharedPointer<const PublicKey> client_pub(new PublicKey(client_priv));

    QSharedPointer<const PublicKeySet> server_pk_set(new PublicKeySet(params, server_pks));

    // Generate ciphertext
    QSharedPointer<ClientCiphertext> c = CiphertextFactory::CreateClientCiphertext(
        params, server_pk_set, author_pk);

    c->SetProof(0, client_priv);

    QSharedPointer<ElGamalClientCiphertext> egc;
    if((egc = qSharedPointerDynamicCast<ElGamalClientCiphertext>(c)) && !egc.isNull()) {
      const Integer q = params->GetGroupOrder();
      ASSERT_TRUE(egc->GetChallenge1() > 0 && egc->GetChallenge1() < q);
      ASSERT_TRUE(egc->GetChallenge2() > 0 && egc->GetChallenge2() < q);

      ASSERT_EQ(params->GetNElements()+1, egc->GetResponses().count());
      foreach(const Integer &i, egc->GetResponses()) {
        ASSERT_TRUE(i > 0 || i < q);
      }

      // Make sure all values are distinct
      QSet<QByteArray> set;
      set.insert(egc->GetChallenge1().GetByteArray());
      set.insert(egc->GetChallenge2().GetByteArray());
      foreach(const Integer &i, egc->GetResponses()) {
        set.insert(i.GetByteArray());
        EXPECT_TRUE(i.GetByteArray().count());
        qDebug() << i.GetByteArray().toHex();
      }

      ASSERT_EQ(params->GetNElements()+3, set.count());
    }

    ASSERT_TRUE(c->VerifyProof(0, client_pub));
  }

  TEST(BlogDrop, CppIntegerClientProof) {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(CryptoFactory::CryptoPP);
    for(int i=0; i<10; i++) {
      TestClientOnce(Parameters::Parameters::IntegerElGamalTestingFixed());
    }
    cf.SetLibrary(cname);
  }

  TEST(BlogDrop, OpenIntegerClientProof) {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(CryptoFactory::OpenSSL);
    for(int i=0; i<10; i++) {
      TestClientOnce(Parameters::Parameters::IntegerElGamalTestingFixed());
    }
    cf.SetLibrary(cname);
  }

  TEST(BlogDrop, CppECClientProof) {
    for(int i=0; i<10; i++) {
      TestClientOnce(Parameters::Parameters::CppECElGamalProductionFixed());
    }
  }

  TEST(BlogDrop, OpenECClientProof) {
    for(int i=0; i<10; i++) {
      TestClientOnce(Parameters::Parameters::OpenECElGamalProductionFixed());
    }
  }

  TEST(BlogDrop, PairingClientProof) {
    for(int i=0; i<10; i++) {
      TestClientOnce(Parameters::Parameters::PairingProductionFixed());
    }
  }

  void TestAuthorOnce(QSharedPointer<const Parameters> params) 
  {

    // Generate an author PK
    QSharedPointer<const PrivateKey> author_priv(new PrivateKey(params));
    QSharedPointer<const PublicKey> author_pk(new PublicKey(author_priv));

    QList<QSharedPointer<const PublicKey> > server_pks;
    const int nkeys = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
    for(int i=0; i<nkeys; i++) {
      QSharedPointer<const PrivateKey> priv(new PrivateKey(params));
      QSharedPointer<const PublicKey> pub(new PublicKey(priv));
      server_pks.append(pub);
    }

    QSharedPointer<const PrivateKey> client_priv(new PrivateKey(params));
    QSharedPointer<const PublicKey> client_pub(new PublicKey(client_priv));

    QSharedPointer<const PublicKeySet> server_pk_set(new PublicKeySet(params, server_pks));

    // Get a random plaintext
    Plaintext m(params);
    m.SetRandom();

    // Generate ciphertext
    QSharedPointer<ClientCiphertext> c = CiphertextFactory::CreateClientCiphertext(
        params, server_pk_set, author_pk);
    c->SetAuthorProof(0, client_priv, author_priv, m);

    QSharedPointer<ElGamalClientCiphertext> egc;
    if((egc = qSharedPointerDynamicCast<ElGamalClientCiphertext>(c)) && !egc.isNull()) {
      const Integer q = params->GetGroupOrder();
      ASSERT_TRUE(egc->GetChallenge1() > 0 && egc->GetChallenge1() < q);
      ASSERT_TRUE(egc->GetChallenge2() > 0 && egc->GetChallenge2() < q);

      ASSERT_EQ(params->GetNElements()+1, egc->GetResponses().count());
      foreach(const Integer &i, egc->GetResponses()) {
        ASSERT_TRUE(i > 0 || i < q);
      }

      // Make sure all values are distinct
      QSet<QByteArray> set;
      set.insert(egc->GetChallenge1().GetByteArray());
      set.insert(egc->GetChallenge2().GetByteArray());
      foreach(const Integer &i, egc->GetResponses()) {
        set.insert(i.GetByteArray());
      }

      ASSERT_EQ(params->GetNElements()+3, set.count());
    }

    ASSERT_TRUE(c->VerifyProof(0, client_pub));
  }

  TEST(BlogDrop, CppIntegerElGamalAuthorProof) {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(CryptoFactory::CryptoPP);
    for(int i=0; i<10; i++) {
      TestAuthorOnce(Parameters::Parameters::IntegerElGamalTestingFixed());
    }
    cf.SetLibrary(cname);
  }

  TEST(BlogDrop, OpenIntegerElGamalAuthorProof) {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(CryptoFactory::OpenSSL);
    for(int i=0; i<10; i++) {
      TestAuthorOnce(Parameters::Parameters::IntegerElGamalTestingFixed());
    }
    cf.SetLibrary(cname);
  }

  TEST(BlogDrop, CppECElGamalAuthorProof) {
    for(int i=0; i<10; i++) {
      TestAuthorOnce(Parameters::Parameters::CppECElGamalProductionFixed());
    }
  }

  TEST(BlogDrop, OpenECElGamalAuthorProof) {
    for(int i=0; i<10; i++) {
      TestAuthorOnce(Parameters::Parameters::OpenECElGamalProductionFixed());
    }
  }

  TEST(BlogDrop, PairingAuthorProof) {
    for(int i=0; i<10; i++) {
      TestAuthorOnce(Parameters::Parameters::PairingProductionFixed());
    }
  }
  
  void ElGamalEndToEndOnce(QSharedPointer<const Parameters> params, bool random = true)
  {
    int nservers; 
    int nclients; 
    int author_idx;
    if(random) {
      nservers = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
      nclients = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
      author_idx = Random::GetInstance().GetInt(0, nclients);
    } else {
      nservers = 10;
      nclients = 100;
      author_idx = 0;
    }

    // Generate an author PK
    const QSharedPointer<const PrivateKey> author_priv(new PrivateKey(params));
    const QSharedPointer<const PublicKey> author_pk(new PublicKey(author_priv));

    qDebug() << "SERVER_PK";
    // Generate list of server pks
    QList<QSharedPointer<const PublicKey> > server_pks;
    QList<QSharedPointer<const PrivateKey> > server_sks;

    for(int i=0; i<nservers; i++) {
      QSharedPointer<const PrivateKey> priv(new PrivateKey(params));
      QSharedPointer<const PublicKey> pub(new PublicKey(priv));
      server_sks.append(priv);
      server_pks.append(pub);
    }

    qDebug() << "CLIENT_PK";
    // Generate list of client pks
    QList<QSharedPointer<const PublicKey> > client_pks;
    QList<QSharedPointer<const PrivateKey> > client_sks;
    for(int i=0; i<nclients; i++) {
      QSharedPointer<const PrivateKey> priv(new PrivateKey(params));
      QSharedPointer<const PublicKey> pub(new PublicKey(priv));
      client_sks.append(priv);
      client_pks.append(pub);
    }
    QSharedPointer<const PublicKeySet> server_pk_set(new PublicKeySet(params, server_pks));

    qDebug() << "CREATE_SERVER";
    QList<BlogDropServer> servers;
    for(int i=0; i<nservers; i++) {
      servers.append(BlogDropServer(params, server_sks[i], server_pk_set, author_pk));
    }

    qDebug() << "RANDOM_PLAINTEXT";
    // Get a random plaintext
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    BlogDropAuthor auth(params, client_sks[author_idx], server_pk_set, author_priv);

    QByteArray msg(auth.MaxPlaintextLength(), 0);
    rand->GenerateBlock(msg);

    QList<QList<QByteArray> > for_servers;
    for(int server_idx=0; server_idx<nservers; server_idx++) {
      for_servers.append(QList<QByteArray>());
    }

    qDebug() << "CLIENTS";
    // Generate client ciphertext and give it to all servers
    for(int client_idx=0; client_idx<nclients; client_idx++) {
      QByteArray c = BlogDropClient(params, client_sks[client_idx], server_pk_set, 
            author_pk).GenerateCoverCiphertext();

      if(client_idx == author_idx) {
        ASSERT_TRUE(auth.GenerateAuthorCiphertext(c, msg)); 
      }

      for(int server_idx=0; server_idx<nservers; server_idx++) {
        for_servers[server_idx].append(c);
      }
    }

    qDebug() << "ADD_CLIENT_TO_SERVER";
    for(int server_idx=0; server_idx<nservers; server_idx++) {
      servers[server_idx].AddClientCiphertexts(for_servers[server_idx], client_pks);
    }

    qDebug() << "CLOSE_BIN";
    // Generate server ciphertext and pass it to all servers
    QList<QByteArray> s;
    for(int i=0; i<nservers; i++) {
      qDebug() << "----------SERVER"<<i<<"--------------";
      s.append(servers[i].CloseBin());
    }

    qDebug() << "ADD_SERVER_TO_SERVER";
    for(int i=0; i<nservers; i++) {
      for(int j=0; j<nservers; j++) {
        qDebug() << "----------SERVER"<<i<<"--------------";
        ASSERT_TRUE(servers[j].AddServerCiphertext(servers[i].GetPublicKey(), s[i]));
      }
    }

    qDebug() << "REVEAL";
    // Reveal the plaintext
    for(int i=0; i<nservers; i++) {
      qDebug() << "REVEAL" << i;
      QByteArray out;
      ASSERT_TRUE(servers[i].RevealPlaintext(out));
      ASSERT_EQ(msg, out);
    }
  }
  

  TEST(BlogDrop, CppIntegerElGamalEndToEnd) 
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(CryptoFactory::CryptoPP);
    ElGamalEndToEndOnce(Parameters::Parameters::IntegerElGamalProductionFixed(), false);
    cf.SetLibrary(cname);
  }

  TEST(BlogDrop, OpenIntegerElgamalEndToEnd) 
  { 
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(CryptoFactory::OpenSSL);
    ElGamalEndToEndOnce(Parameters::Parameters::IntegerElGamalProductionFixed(), false);
    cf.SetLibrary(cname);
  }


  TEST(BlogDrop, CppECElGamalEndToEnd) 
  {
    ElGamalEndToEndOnce(Parameters::Parameters::CppECElGamalProductionFixed(), false);
  }

  TEST(BlogDrop, OpenECElGamalEndToEnd) 
  {
    ElGamalEndToEndOnce(Parameters::Parameters::OpenECElGamalProductionFixed(), false);
  }

  TEST(BlogDrop, PairingEndToEnd) 
  {
    ElGamalEndToEndOnce(Parameters::Parameters::PairingProductionFixed(), false);
  }

  void HashingEndToEndOnce(QSharedPointer<const Parameters> params, bool random = true)
  {
    int nservers; 
    int nclients; 
    int author_idx;
    if(random) {
      nservers = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
      nclients = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
      author_idx = Random::GetInstance().GetInt(0, nclients);
    } else {
      nservers = 10;
      nclients = 100;
      author_idx = 0;
    }

    // Generate an author PK
    const QSharedPointer<const PrivateKey> author_priv(new PrivateKey(params));
    const QSharedPointer<const PublicKey> author_pk(new PublicKey(author_priv));

    qDebug() << "SERVER_PK";
    // Generate list of server pks
    QList<QSharedPointer<const PublicKey> > server_pks;
    QList<QSharedPointer<const PrivateKey> > server_sks;

    for(int i=0; i<nservers; i++) {
      QSharedPointer<const PrivateKey> priv(new PrivateKey(params));
      QSharedPointer<const PublicKey> pub(new PublicKey(priv));
      server_sks.append(priv);
      server_pks.append(pub);
    }

    qDebug() << "CLIENT_PK";
    // Generate list of client pks
    QList<QSharedPointer<const PublicKey> > client_pks;
    QList<QSharedPointer<const PrivateKey> > client_sks;
    for(int i=0; i<nclients; i++) {
      QSharedPointer<const PrivateKey> priv(new PrivateKey(params));
      QSharedPointer<const PublicKey> pub(new PublicKey(priv));
      client_sks.append(priv);
      client_pks.append(pub);
    }

    // for each server/client
    QList<QSharedPointer<const PrivateKey> > master_client_priv;
    QList<QSharedPointer<const PublicKey> > master_client_pub;
    QList<QSharedPointer<const PrivateKey> > master_server_priv;
    QList<QSharedPointer<const PublicKey> > master_server_pub;

    for(int i=0; i<nclients; i++) { 
      QSharedPointer<const PrivateKey> priv;
      QSharedPointer<const PublicKey> pub;
      QList<QSharedPointer<const PublicKey> > commits;
      
      BlogDropUtils::GetMasterSharedSecrets(params, client_sks[i], server_pks, priv, pub, commits);

      master_client_pub.append(pub);
      master_client_priv.append(priv);
    }

    for(int i=0; i<nservers; i++) { 
      QSharedPointer<const PrivateKey> priv;
      QSharedPointer<const PublicKey> pub;
      QList<QSharedPointer<const PublicKey> > commits;
      
      BlogDropUtils::GetMasterSharedSecrets(params, server_sks[i], client_pks, priv, pub, commits);

      master_server_pub.append(pub);
      master_server_priv.append(priv);
    }

    QSharedPointer<const PublicKeySet> master_server_set(new PublicKeySet(params, master_server_pub));

    qDebug() << "CREATE_SERVER";
    QList<BlogDropServer> servers;
    for(int i=0; i<nservers; i++) {
      servers.append(BlogDropServer(params, master_server_priv[i], master_server_set, author_pk));
    }

    qDebug() << "RANDOM_PLAINTEXT";
    // Get a random plaintext
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    BlogDropAuthor auth(params, master_client_priv[author_idx], master_server_set, author_priv);

    QByteArray msg(auth.MaxPlaintextLength(), 0);
    rand->GenerateBlock(msg);

    QList<QList<QByteArray> > for_servers;
    for(int server_idx=0; server_idx<nservers; server_idx++) {
      for_servers.append(QList<QByteArray>());
    }

    qDebug() << "CLIENTS";
    // Generate client ciphertext and give it to all servers
    for(int client_idx=0; client_idx<nclients; client_idx++) {
      QByteArray c = BlogDropClient(params, master_client_priv[client_idx], master_server_set, 
            author_pk).GenerateCoverCiphertext();

      if(client_idx == author_idx) {
        ASSERT_TRUE(auth.GenerateAuthorCiphertext(c, msg)); 
      }

      for(int server_idx=0; server_idx<nservers; server_idx++) {
        for_servers[server_idx].append(c);
      }
    }

    qDebug() << "ADD_CLIENT_TO_SERVER";
    for(int server_idx=0; server_idx<nservers; server_idx++) {
      servers[server_idx].AddClientCiphertexts(for_servers[server_idx], master_client_pub);
    }

    qDebug() << "CLOSE_BIN";
    // Generate server ciphertext and pass it to all servers
    QList<QByteArray> s;
    for(int i=0; i<nservers; i++) {
      qDebug() << "----------SERVER"<<i<<"--------------";
      s.append(servers[i].CloseBin());
    }

    qDebug() << "ADD_SERVER_TO_SERVER";
    for(int i=0; i<nservers; i++) {
      for(int j=0; j<nservers; j++) {
        qDebug() << "----------SERVER"<<i<<"--------------";
        ASSERT_TRUE(servers[j].AddServerCiphertext(servers[i].GetPublicKey(), s[i]));
      }
    }

    qDebug() << "REVEAL";
    // Reveal the plaintext
    for(int i=0; i<nservers; i++) {
      qDebug() << "REVEAL" << i;
      QByteArray out;
      ASSERT_TRUE(servers[i].RevealPlaintext(out));
      ASSERT_EQ(msg, out);
    }
  }

  TEST(BlogDrop, CppIntegerHashingEndToEnd) 
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(CryptoFactory::CryptoPP);
    HashingEndToEndOnce(Parameters::Parameters::IntegerHashingProductionFixed(), false);
    cf.SetLibrary(cname);
  }

  TEST(BlogDrop, OpenIntegerHashingEndToEnd) 
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(CryptoFactory::OpenSSL);
    HashingEndToEndOnce(Parameters::Parameters::IntegerHashingProductionFixed(), false);
    cf.SetLibrary(cname);
  }

  TEST(BlogDrop, CppECHashingEndToEnd) 
  {
    HashingEndToEndOnce(Parameters::Parameters::CppECHashingProductionFixed(), false);
  }

  TEST(BlogDrop, OpenECHashingEndToEnd) 
  {
    HashingEndToEndOnce(Parameters::Parameters::OpenECHashingProductionFixed(), false);
  }

  TEST(BlogDrop, XorEndToEnd) 
  {
    HashingEndToEndOnce(Parameters::Parameters::XorTestingFixed(), false);
  }


}
}

