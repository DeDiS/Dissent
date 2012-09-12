#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  void IntegerBasicTest()
  {
    Dissent::Crypto::Integer int0(5);
    Dissent::Crypto::Integer int1(6);

    EXPECT_NE(int0, int1);
    EXPECT_EQ(int0, int1 - 1);
    EXPECT_EQ(int0 + 1, int1);
    EXPECT_TRUE(int0 < int1);
    EXPECT_TRUE(int1 > int0);
    EXPECT_TRUE(int0 <= int1);
    EXPECT_TRUE(int1 >= int0);
    EXPECT_TRUE(int0 + 1 <= int1);
    EXPECT_TRUE(int1 - 1 >= int0);

    std::swap(int0, int1);

    EXPECT_NE(int0, int1);
    EXPECT_EQ(int0, int1 + 1);
    EXPECT_EQ(int0 - 1, int1);
    EXPECT_TRUE(int0 > int1);
    EXPECT_TRUE(int1 < int0);
    EXPECT_TRUE(int0 >= int1);
    EXPECT_TRUE(int1 <= int0);
    EXPECT_TRUE(int0 - 1 >= int1);
    EXPECT_TRUE(int1 + 1 <= int0);

    EXPECT_EQ(int0 * int1, Integer(30));
    EXPECT_EQ(Integer(30) / int0, int1);
    EXPECT_EQ(Integer(30) / int1, int0);
  }

  void IntegerTestNull()
  {
    Dissent::Crypto::Integer int0 = Dissent::Crypto::Integer(QByteArray());
    Dissent::Crypto::Integer int1 = Dissent::Crypto::Integer(0);
    EXPECT_EQ(int0, int1);
  }

  void IntegerTestCopy()
  {
    Dissent::Crypto::Integer int0(5);
    Dissent::Crypto::Integer int1 = int0;

    EXPECT_EQ(int0, int1);
    int0 += 5;
    EXPECT_NE(int0, int1);
  }

  void IntegerInvalidString()
  {
    Integer base;
    QString bad = "ABCD";
    QString good = base.ToString();

    EXPECT_NE(bad, Integer(bad).ToString());
    EXPECT_EQ(base, Integer(good));
  }

  void IntegerRandom()
  {
    Integer val0 = Integer::GetRandomInteger(1024);
    Integer val1 = Integer::GetRandomInteger(0, val0);
    Integer val2 = Integer::GetRandomInteger(0, val0, true);

    EXPECT_NE(val0, val1);
    EXPECT_NE(val0, val2);
    EXPECT_NE(val1, val2);
    EXPECT_TRUE(val1 < val0);
    EXPECT_TRUE(val2 < val0);
  }

  TEST(Integer, CppBasic)
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(CryptoFactory::CryptoPP);
    IntegerBasicTest();
    cf.SetLibrary(cname);
  }

  TEST(Integer, CppNull)
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(CryptoFactory::CryptoPP);
    IntegerTestNull();
    cf.SetLibrary(cname);
  }

  TEST(Integer, CppTestCopy)
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(CryptoFactory::CryptoPP);
    IntegerTestCopy();
    cf.SetLibrary(cname);
  }

  TEST(Integer, CppInvalidString)
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(CryptoFactory::CryptoPP);
    IntegerInvalidString();
    cf.SetLibrary(cname);
  }

  TEST(Integer, CppPow)
  {
    Integer base(10);
    Integer exp(100);
    EXPECT_EQ(exp, base.Pow(Integer(10), Integer(101)));
    EXPECT_EQ(Integer(0), base.Pow(Integer(10), Integer(100)));
  }

  TEST(Integer, CppModInverse)
  {
    for(int i=0; i<10; i++) {
      Integer p = Integer::GetRandomInteger(1024, true);
      Integer a = Integer::GetRandomInteger(0, p);
      Integer inv = a.ModInverse(p);
      Integer out = (a*inv)%p;

      ASSERT_TRUE(a > 0);
      ASSERT_TRUE(p > a);

      qDebug() << "a" << a.GetByteArray().toHex();
      qDebug() << "p" << p.GetByteArray().toHex();
      qDebug() << "out" << out.GetByteArray().toHex();

      ASSERT_EQ(Integer(1), out);
    }
  }
  
  TEST(Integer, CppRandom)
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(CryptoFactory::CryptoPP);
    IntegerRandom();
    cf.SetLibrary(cname);
  }

  TEST(Integer, Int32)
  {
    Integer test(5);
    EXPECT_EQ(5, test.GetInt32());
    test = 0x7f8f8f8f;
    EXPECT_EQ(0x7f8f8f8f, test.GetInt32());
  }

  TEST(Integer, ModInverse)
  {
    Integer mod = Integer::GetRandomInteger(1024);
    // mod should be prime to ensure (higher likelihood of) multiplicative inverse
    mod = Integer::GetRandomInteger(1024, mod, true);
    Integer val = Integer::GetRandomInteger(1024, mod);
    Integer mi = val.ModInverse(mod);
    Integer result = (val * mi) % mod;
    qDebug() << result.ToString() << (val < mod) << (mi < mod);
    EXPECT_EQ(result, 1);
  }

  TEST(Integer, OpenBasic)
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(CryptoFactory::OpenSSL);
    IntegerBasicTest();
    cf.SetLibrary(cname);
  }

  TEST(Integer, OpenNull)
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(CryptoFactory::OpenSSL);
    IntegerTestNull();
    cf.SetLibrary(cname);
  }

  TEST(Integer, OpenTestCopy)
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(CryptoFactory::OpenSSL);
    IntegerTestCopy();
    cf.SetLibrary(cname);
  }

  TEST(Integer, OpenInvalidString)
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(CryptoFactory::OpenSSL);
    IntegerInvalidString();
    cf.SetLibrary(cname);
  }

  TEST(Integer, OpenPow)
  {
    Integer base(10);
    Integer exp(100);
    EXPECT_EQ(exp, base.Pow(Integer(10), Integer(101)));
    EXPECT_EQ(Integer(0), base.Pow(Integer(10), Integer(100)));

    for(int i=0; i<10; i++) {
      Integer p = Integer::GetRandomInteger(1024, true);
      Integer a = Integer::GetRandomInteger(0, p);
      Integer b = Integer::GetRandomInteger(0, p);
      Integer e1 = Integer::GetRandomInteger(0, p);
      Integer e2 = Integer::GetRandomInteger(0, p);


      EXPECT_EQ(p.PowCascade(a, e1, b, e2), 
          (a.Pow(e1, p) * b.Pow(e2, p))%p);

      EXPECT_EQ(Integer(1), a.Pow(0, p));
      EXPECT_EQ(a, a.Pow(1, p));
    }
  }

  TEST(Integer, OpenModInverse)
  {
    for(int i=0; i<10; i++) {
      Integer p = Integer::GetRandomInteger(1024, true);
      Integer a = Integer::GetRandomInteger(0, p);

      Integer na = a * Integer(-1);
      ASSERT_EQ(na, a - (2*a));

      ASSERT_EQ((a-p)%p, a);
      ASSERT_EQ((a-(40*p))%p, a);

      Integer inv = a.ModInverse(p);
      Integer out = (a*inv)%p;

      ASSERT_TRUE(a > 0);
      ASSERT_TRUE(p > a);

      qDebug() << "a" << a.GetByteArray().toHex();
      qDebug() << "p" << p.GetByteArray().toHex();
      qDebug() << "out" << out.GetByteArray().toHex();

      ASSERT_EQ(Integer(1), out);
    }
  }
  
  TEST(Integer, OpenRandom)
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(CryptoFactory::OpenSSL);
    IntegerRandom();
    cf.SetLibrary(cname);
  }
}
}
