#include "AbstractGroupHelpers.hpp"
#include "DissentTest.hpp"
#include <cryptopp/ecp.h>
#include <cryptopp/nbtheory.h>

namespace Dissent {
namespace Tests {

  void TestPlaintextEmpty(QSharedPointer<const Parameters> params)
  {
    Plaintext p(params);
    QByteArray out;
    EXPECT_FALSE(p.Decode(out));
    EXPECT_EQ(QByteArray(), out);
  }

  TEST(BlogDrop, IntegerPlaintextEmpty) {
    TestPlaintextEmpty(Parameters::Parameters::IntegerElGamalTestingFixed());
  }

  TEST(BlogDrop, CppECPlaintextEmpty) 
  {
    TestPlaintextEmpty(Parameters::Parameters::CppECElGamalProductionFixed());
  }

  TEST(BlogDrop, OpenECPlaintextEmpty) 
  {
    TestPlaintextEmpty(Parameters::Parameters::OpenECElGamalProductionFixed());
  }

  TEST(BlogDrop, PairingECPlaintextEmpty) 
  {
    TestPlaintextEmpty(Parameters::Parameters::PairingProductionFixed());
  }

  void TestPlaintextShort(QSharedPointer<const Parameters> params)
  {
    Plaintext p(params);

    QByteArray shorts("shorts");
    p.Encode(shorts);

    QByteArray out;
    EXPECT_TRUE(p.Decode(out));
    EXPECT_EQ(shorts, out);
  }

  TEST(BlogDrop, IntegerPlaintextShort) {
    TestPlaintextShort(Parameters::Parameters::IntegerElGamalTestingFixed());
  }

  TEST(BlogDrop, CppECPlaintextShort) {
    TestPlaintextShort(Parameters::Parameters::CppECElGamalProductionFixed());
  }

  TEST(BlogDrop, OpenECPlaintextShort) {
    TestPlaintextShort(Parameters::Parameters::OpenECElGamalProductionFixed());
  }

  TEST(BlogDrop, PairingPlaintextShort) {
    TestPlaintextShort(Parameters::Parameters::PairingProductionFixed());
  }

  void TestPlaintextRandom(QSharedPointer<const Parameters> params, int divby)
  {
    Plaintext p(params);

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    EXPECT_EQ(params->GetGroupOrder(), params->GetKeyGroup()->GetOrder());
    EXPECT_EQ(params->GetGroupOrder(), params->GetMessageGroup()->GetOrder());

    for(int i=0; i<10; i++) {
      QByteArray msg(Plaintext::CanFit(params)/divby, 0);
      rand->GenerateBlock(msg);

      p.Encode(msg);

      QByteArray output;
      EXPECT_TRUE(p.Decode(output));
      EXPECT_GT(output.count(), 0);
      EXPECT_LT(output.count(), (params->GetNElements()*
            (params->GetMessageGroup()->GetOrder().GetByteCount()/divby)));
      EXPECT_GT(output.count(), (params->GetNElements()*
            ((params->GetMessageGroup()->GetOrder().GetByteCount()-5)/divby)));
      EXPECT_EQ(msg, output);
    }
  }

  TEST(BlogDrop, IntegerPlaintextRandom) {
    TestPlaintextRandom(Parameters::Parameters::IntegerElGamalTestingFixed(), 1);
    TestPlaintextRandom(Parameters::Parameters::IntegerElGamalTestingFixed(), 2);
    TestPlaintextRandom(Parameters::Parameters::IntegerElGamalTestingFixed(), 4);
  }

  TEST(BlogDrop, CppECPlaintextRandom) {
    TestPlaintextRandom(Parameters::Parameters::CppECElGamalProductionFixed(), 1);
    TestPlaintextRandom(Parameters::Parameters::CppECElGamalProductionFixed(), 2);
    TestPlaintextRandom(Parameters::Parameters::CppECElGamalProductionFixed(), 4);
  }

  TEST(BlogDrop, OpenECPlaintextRandom) {
    TestPlaintextRandom(Parameters::Parameters::OpenECElGamalProductionFixed(), 1);
    TestPlaintextRandom(Parameters::Parameters::OpenECElGamalProductionFixed(), 2);
    TestPlaintextRandom(Parameters::Parameters::OpenECElGamalProductionFixed(), 4);
  }

  TEST(BlogDrop, PairingPlaintextRandom) {
    TestPlaintextRandom(Parameters::Parameters::PairingProductionFixed(), 1);
    TestPlaintextRandom(Parameters::Parameters::PairingProductionFixed(), 2);
    TestPlaintextRandom(Parameters::Parameters::PairingProductionFixed(), 4);
  }

  void TestKeys(QSharedPointer<const Parameters> params)
  {
    for(int i=0; i<20; i++) {
      PrivateKey priv(params);
      Integer x = priv.GetInteger();

      PublicKey pub(priv);
      Element gx = pub.GetElement();

      ASSERT_TRUE(x < params->GetKeyGroup()->GetOrder());
      ASSERT_TRUE(x > 0);
      ASSERT_EQ(gx, params->GetKeyGroup()->Exponentiate(params->GetKeyGroup()->GetGenerator(), x));

      PrivateKey priv2(params);
      PublicKey pub2(priv);

      QByteArray proof = pub.ProveKnowledge(priv);
      ASSERT_TRUE(pub.VerifyKnowledge(proof));

      QByteArray proof2 = pub.ProveKnowledge(priv2);
      ASSERT_FALSE(pub.VerifyKnowledge(proof2));
    }
  }

  TEST(BlogDrop, IntegerKeys) {
    TestKeys(Parameters::Parameters::IntegerElGamalTestingFixed());
  }

  TEST(BlogDrop, CppECKeys) {
    TestKeys(Parameters::Parameters::CppECElGamalProductionFixed());
  }

  TEST(BlogDrop, OpenECKeys) {
    TestKeys(Parameters::Parameters::OpenECElGamalProductionFixed());
  }

  TEST(BlogDrop, PairingKeys) {
    TestKeys(Parameters::Parameters::PairingProductionFixed());
  }

  void TestPublicKeySet(QSharedPointer<const Parameters> params)
  {
    const int nkeys = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);

    QList<QSharedPointer<const PublicKey> > keys;
    Element prod = params->GetKeyGroup()->GetIdentity();
    for(int i=0; i<nkeys; i++) {
      QSharedPointer<const PrivateKey> priv(new PrivateKey(params));
      QSharedPointer<const PublicKey> pub(new PublicKey(priv));
      keys.append(pub);

      prod = params->GetKeyGroup()->Multiply(prod, pub->GetElement());
    }

    PublicKeySet keyset(params, keys);
    ASSERT_EQ(prod, keyset.GetElement());
  }

  TEST(BlogDrop, IntegerPublicKeySet) {
    TestPublicKeySet(Parameters::Parameters::IntegerElGamalTestingFixed());
  }

  TEST(BlogDrop, CppECPublicKeySet) {
    TestPublicKeySet(Parameters::Parameters::CppECElGamalProductionFixed());
  }

  TEST(BlogDrop, OpenECPublicKeySet) {
    TestPublicKeySet(Parameters::Parameters::OpenECElGamalProductionFixed());
  }
 
  TEST(BlogDrop, PairingPublicKeySet) {
    TestPublicKeySet(Parameters::Parameters::PairingProductionFixed());
  } 

  void BenchmarkGroup(QSharedPointer<const Parameters> params,
      QSharedPointer<const AbstractGroup> group)
  {
    Element a1 = group->RandomElement();
    Integer e1 = group->RandomExponent();
    Element a2 = group->RandomElement();
    Integer e2 = group->RandomExponent();
    for(int i=0; i<(100*params->GetNElements()); i++) {
      Element res = group->CascadeExponentiate(a1, e1, a2, e2);
      //Element res = group->Exponentiate(a1, e1);
    }
  }

  void Benchmark(QSharedPointer<const Parameters> params)
  {
    BenchmarkGroup(params, params->GetMessageGroup());
    BenchmarkGroup(params, params->GetKeyGroup());
  }

  TEST(BlogDrop, BenchmarkInteger) 
  {
    Benchmark(Parameters::Parameters::IntegerElGamalProductionFixed());
  }

  TEST(BlogDrop, BenchmarkCppEC) 
  {
    Benchmark(Parameters::Parameters::CppECElGamalProductionFixed());
  }

  TEST(BlogDrop, BenchmarkOpenEC) 
  {
    Benchmark(Parameters::Parameters::OpenECElGamalProductionFixed());
  }

  TEST(BlogDrop, BenchmarkPairing) 
  {
    Benchmark(Parameters::Parameters::PairingProductionFixed());
  }

  /*
  TEST(BlogDrop, BenchmarkIntegerRaw) 
  {
    const char *bytes_p = "0xfddb8c605ec022e00980a93695b6e16f776f8db658c40163d"
                          "2cfb2f57d0d685076311697065cf78657fa6819000e9ea923c1"
                          "b488cd734f7c8585e97f7515bad667ecba98c4c271db8126703"
                          "a4d4e62238aad384d69f5ccb77fa0fb2569879ca672be6a9228"
                          "0ada08627be1b96371964b35f0e8ac655014a9293ac9dcf1e26"
                          "c9a43a4027ee504d06d60d3819dabaec3268b950932376d146a"
                          "75debb715b366e6fbc3efbb31960382798496dab78f03460b99"
                          "cf204153084ea8e6a6a32fcefa8106f0a1e24246681ba0e2e47"
                          "365d7e84016fd3e2f3ed72022a61c981c3194206d727fceab01"
                          "781cdcc0d3b2c680aa7573471fe781c2e081354cbcf7e94a6a1"
                          "c9df";
    const char *bytes_g = "0x02";

    CryptoPP::Integer p(bytes_p);
    CryptoPP::Integer g(bytes_g);

    CryptoPP::Integer b = g;
    for(int i=0; i<10000; i++) {
      // Get random integer a in [1, q)
      Integer tmp = Integer::GetRandomInteger(0, 
          Integer((Integer(QByteArray::fromHex(bytes_p))-1)/2), false); 
      CryptoPP::Integer exp_a(tmp.GetByteArray().constData());
      // a = take g^a 
      b = a_exp_b_mod_c(g, exp_a, p);
    }
  }
   
  TEST(BlogDrop, BenchmarkECRaw) {
    // RFC 5903 - 256-bit curve
    const char *modulus = "0xFFFFFFFF00000001000000000000000000000000FFFFFFFFF"
                          "FFFFFFFFFFFFFFF";
    const char *b =       "0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63"
                          "BCE3C3E27D2604B";
    const char *q =       "0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F"
                          "3B9CAC2FC632551";
    const char *gx =      "0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F"
                          "4A13945D898C296";
    const char *gy =      "0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECEC"
                          "BB6406837BF51F5";

    CryptoPP::Integer m(modulus);
    ASSERT_TRUE(CryptoPP::IsPrime(m));

    // a = -3
    CryptoPP::ECP ecp(CryptoPP::Integer(modulus), 
        CryptoPP::Integer(-3L), CryptoPP::Integer(b));

    CryptoPP::Integer i_gx(gx);
    CryptoPP::Integer i_gy(gy);
    CryptoPP::ECPPoint g(i_gx, i_gy);

    ASSERT_TRUE(ecp.VerifyPoint(g));

    // a = take g^a 
    CryptoPP::ECPPoint point_b;
    for(int i=0; i<10000; i++) {
      // Get random integer a in [1, q)
      Integer tmp = Integer::GetRandomInteger(0, Integer(QByteArray(q)), false); 
      CryptoPP::Integer exp_a(tmp.GetByteArray().constData());

      point_b = ecp.ScalarMultiply(g, exp_a);
    }
  }
  */
}
}

