
#include "IntegerElementData.hpp"
#include "IntegerGroup.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  IntegerGroup::IntegerGroup(Integer p, Integer g) :
      _p(p), 
      _g(g),
      _q((p-1)/2)
    {};

  IntegerGroup::IntegerGroup(const char *p_bytes, const char *g_bytes) :
    _p(QByteArray::fromHex(p_bytes)),
    _g(QByteArray::fromHex(g_bytes)),
    _q((_p-1)/2)
  {
    Q_ASSERT(_p>0);
    Q_ASSERT(_q>0);
    Q_ASSERT(_g>0);

    if(_g.Pow(2, _p) == 1)
      qFatal("g does not generate G*_p");
  }

  QSharedPointer<IntegerGroup> IntegerGroup::Generate(int) 
  {
    qFatal("Generate not yet supported");
    return QSharedPointer<IntegerGroup>(new IntegerGroup(Integer(), Integer()));
  }

  QSharedPointer<IntegerGroup> IntegerGroup::TestingFixed() 
  {
    const char *bytes_p = "0xd0a5cae1cd4b9ebbd66c5172d9cd33ec61ca04e3abd2d5afb"
                          "43f0a5ddd18d57b";
    const char *bytes_g = "0x03";

    return QSharedPointer<IntegerGroup>(new IntegerGroup(bytes_p, bytes_g));
  }

  QSharedPointer<IntegerGroup> IntegerGroup::Production2048Fixed() 
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

    return QSharedPointer<IntegerGroup>(new IntegerGroup(bytes_p, bytes_g));
  }

  QSharedPointer<IntegerGroup> IntegerGroup::Production1024Fixed() 
  {
    const char *bytes_p = "0xfd8a16fc2afdaeb2ea62b66b355f73e6c2fc4349bf4551793"
                          "36ca1b45f75d68da0101cba63c22efd5f72e5c81dc30cf709da"
                          "aef2323e950160926e11ef8cbf40a26496668749218b5620276"
                          "697c2d1536b31042ad846e1e5758d79b3e4e0b5bc4c5d3a4e95"
                          "da4502e9058ea3beade156d8234e35d5164783c57e6135139db"
                          "097";
    const char *bytes_g = "0x02";

    return QSharedPointer<IntegerGroup>(new IntegerGroup(bytes_p, bytes_g));
  }

  QSharedPointer<IntegerGroup> IntegerGroup::Zero() 
  {
    return QSharedPointer<IntegerGroup>(new IntegerGroup(Integer(0), Integer(0))); 
  }


  Element IntegerGroup::Multiply(const Element &a, const Element &b) const
  {
    return Element(new IntegerElementData((GetInteger(a).MultiplyMod(GetInteger(b), _p)))); 
  }

  Element IntegerGroup::Exponentiate(const Element &a, const Integer &exp) const
  {
    return Element(new IntegerElementData(GetInteger(a).Pow(exp, _p))); 
  }
  
  Element IntegerGroup::CascadeExponentiate(const Element &a1, const Integer &e1,
      const Element &a2, const Integer &e2) const
  {
    return Element(new IntegerElementData(
          _p.PowCascade(GetInteger(a1), e1, GetInteger(a2), e2)));
  }

  Element IntegerGroup::Inverse(const Element &a) const
  {
    return Element(new IntegerElementData(GetInteger(a).ModInverse(_p)));
  }
  
  QByteArray IntegerGroup::ElementToByteArray(const Element &a) const
  {
    return GetInteger(a).GetByteArray();
  }
  
  Element IntegerGroup::ElementFromByteArray(const QByteArray &bytes) const 
  {
    return Element(new IntegerElementData(Integer(bytes)));
  }

  bool IntegerGroup::IsElement(const Element &a) const 
  {
    return (GetInteger(a).Pow(_q, _p) == 1);
  }

  bool IntegerGroup::IsIdentity(const Element &a) const 
  {
    return (GetInteger(a) == 1);
  }

  Integer IntegerGroup::RandomExponent() const
  {
    return Integer::GetRandomInteger(1, _q, false); 
  }

  Element IntegerGroup::RandomElement() const
  {
    return Element(new IntegerElementData(_g.Pow(RandomExponent(), _p)));
  }

  Integer IntegerGroup::GetInteger(const Element &e) const
  {
    return IntegerElementData::GetInteger(e.GetData());
  }

  Element IntegerGroup::EncodeBytes(const QByteArray &in) const
  {
    // We can store p bytes minus 2 bytes for padding and one more to be safe
    const int can_read = BytesPerElement();

    if(can_read < 1) qFatal("Illegal parameters");
    if(in.count() > can_read) qFatal("Cannot encode: string is too long");

    // Add initial 0xff byte and trailing 0x00 byte
    QByteArray padded;
    padded.append(0xff);
    padded.append(in.left(can_read));
    padded.append((char)0x00);
    padded.append(0xff);

    // Change byte of padded string until the
    // integer represented by the byte arry is a quadratic
    // residue. We need to be sure that every plaintext
    // message is a quadratic residue modulo p
    const int last = padded.count()-2;

    for(unsigned char pad=0x00; pad < 0xff; pad++) {
      padded[last] = pad;

      Element element(new IntegerElementData(Integer(padded)));
      if(IsElement(element)) {
        return element;
      }
    }

    qFatal("Could not encode message as quadratic residue");
    return Element(new IntegerElementData(Integer(1)));
  }
 
  bool IntegerGroup::DecodeBytes(const Element &a, QByteArray &out) const
  {
    QByteArray data = ElementToByteArray(a);
    if(data.count() < 3) {
      qWarning() << "Tried to decode invalid plaintext (too short):" << data.toHex();
      return false;
    }

    const unsigned char cfirst = data[0];
    const unsigned char clast = data.right(1)[0];
    if(cfirst != 0xff || clast != 0xff) {
      qWarning() << "Tried to decode invalid plaintext (bad padding)";
      return false;
    }

    out = data.mid(1, data.count()-3);
    return true;
  }

  bool IntegerGroup::IsProbablyValid() const
  {
    // g != -1, 0, 1
    if(_g == 0 || _g == 1 || _g == Integer(-1).Modulo(_p))
      return false;

    // g^q = 1
    if(_g.Pow(_q, _p) != 1)
      return false;

    return true;
  }

  QByteArray IntegerGroup::GetByteArray() const
  {
    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);

    stream << _p << _g << _q;

    return out;
  }

  bool IntegerGroup::IsGenerator(const Element &a) const 
  {
    return IsElement(a) 
      && ((Exponentiate(a, GetOrder()) == GetIdentity()))
      && (!(Exponentiate(a, Integer(2)) == GetIdentity()));
  }


}
}
}
