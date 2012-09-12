#include "OpenECElementData.hpp"
#include "OpenECGroup.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  OpenECGroup::OpenECGroup(BIGNUM *p, BIGNUM *q, BIGNUM *a, 
      BIGNUM *b, BIGNUM *gx, BIGNUM *gy, bool is_nist_curve) :
      _p(p),
      _q(q),
      _a(a),
      _b(b),
      _gx(gx),
      _gy(gy),
      _zero(BN_new()),
      _one(BN_new()),
      _data(new MutableData(is_nist_curve)),
      _generator(EC_POINT_new(_data->group)), 
      _field_bytes(BN_num_bytes(_p)-1)
    {
      CHECK_CALL(_data->ctx);
      CHECK_CALL(_data->group);

      CHECK_CALL(BN_zero(_zero));
      CHECK_CALL(BN_one(_one));

      /*
      BN_print_fp(stdout, _p);
      BN_print_fp(stdout, _a);
      BN_print_fp(stdout, _b);
      */

      // Prepare montgomery multiplication mod p
      CHECK_CALL(BN_MONT_CTX_set(_data->mont, _p, _data->ctx));

      // Initialize group
      CHECK_CALL(EC_GROUP_set_curve_GFp(_data->group, _p, _a, _b, _data->ctx));

      // affine coordinates are the "normal" (x,y) pairs
      CHECK_CALL(EC_POINT_set_affine_coordinates_GFp(_data->group, 
            _generator, _gx, _gy, _data->ctx));

      // Cofactor of our curves are always 1
      CHECK_CALL(EC_GROUP_set_generator(_data->group, _generator, _q, _one));

      // Precomupte factors of generator
      CHECK_CALL(EC_GROUP_precompute_mult(_data->group, _data->ctx));
    };

  QSharedPointer<OpenECGroup> OpenECGroup::NewGroup(const Integer &p_in, 
      const Integer &q_in, const Integer &a_in, 
      const Integer &b_in, const Integer &gx_in, 
      const Integer &gy_in, bool is_nist_curve)
  {
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *gx = BN_new();
    BIGNUM *gy = BN_new();

    GetInteger(p, p_in);
    GetInteger(q, q_in);
    GetInteger(a, a_in);
    GetInteger(b, b_in);
    GetInteger(gx, gx_in);
    GetInteger(gy, gy_in);

    return QSharedPointer<OpenECGroup>(new OpenECGroup(p, q, a, b, gx, gy, is_nist_curve));
  }

  OpenECGroup::~OpenECGroup() 
  {
    EC_POINT_clear_free(_generator);

    delete _data;

    BN_clear_free(_p);
    BN_clear_free(_q);
    BN_clear_free(_a);
    BN_clear_free(_b);
    BN_clear_free(_gx);
    BN_clear_free(_gy);
    BN_free(_one);
    BN_free(_zero);
  }

  QSharedPointer<OpenECGroup> OpenECGroup::ProductionFixed() 
  {
    // RFC 5903 - 256-bit curve
    const char *str_p = "FFFFFFFF000000010000000000"
                    "00000000000000FFFFFFFFFFFFFFFFFFFFFFFF";
    const char *str_q = "FFFFFFFF00000000FFFFFFFFFF"
                    "FFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";

    const char *str_a = "-3";
    const char *str_b = "5AC635D8AA3A93E7B3EBBD5576"
                    "9886BC651D06B0CC53B0F63BCE3C3E27D2604B";

    const char *str_gx = "6B17D1F2E12C4247F8BCE6E56"
                     "3A440F277037D812DEB33A0F4A13945D898C296";
    const char *str_gy = "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE3"
                     "3576B315ECECBB6406837BF51F5";

    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *gx = BN_new();
    BIGNUM *gy = BN_new();

    CHECK_CALL(p);
    CHECK_CALL(q);
    CHECK_CALL(a);
    CHECK_CALL(b);
    CHECK_CALL(gx);
    CHECK_CALL(gy);

    BN_hex2bn(&p, str_p);
    BN_hex2bn(&q, str_q);
    BN_hex2bn(&a, str_a);
    BN_hex2bn(&b, str_b);
    BN_hex2bn(&gx, str_gx);
    BN_hex2bn(&gy, str_gy);

    CHECK_CALL(p);
    CHECK_CALL(q);
    CHECK_CALL(a);
    CHECK_CALL(b);
    CHECK_CALL(gx);
    CHECK_CALL(gy);

    return QSharedPointer<OpenECGroup>(new OpenECGroup(p, q, a, b, gx, gy, true));
  }

  Element OpenECGroup::Multiply(const Element &a, const Element &b) const
  {
    EC_POINT *r = EC_POINT_new(_data->group);
    CHECK_CALL(r);

    // r = a + b
    CHECK_CALL(EC_POINT_add(_data->group, r, GetPoint(a), GetPoint(b), _data->ctx));

    return NewElement(r);
  }

  Element OpenECGroup::Exponentiate(const Element &a, const Integer &exp) const
  {
    EC_POINT *r = EC_POINT_new(_data->group);
    CHECK_CALL(r);

    const EC_POINT *ps[1];
    const BIGNUM *ms[1];

    BIGNUM *tmp = BN_new();
    GetInteger(tmp, exp);

    ps[0] = GetPoint(a);
    ms[0] = tmp;

    CHECK_CALL(EC_POINTs_mul(_data->group, r, _zero, 1, ps, ms, _data->ctx));

    BN_clear_free(tmp);

    return NewElement(r);
  }
  
  Element OpenECGroup::CascadeExponentiate(const Element &a1, const Integer &e1,
      const Element &a2, const Integer &e2) const
  {
    EC_POINT *r = EC_POINT_new(_data->group);
    CHECK_CALL(r);

    const EC_POINT *ps[2];
    const BIGNUM *ms[2];

    BIGNUM *tmp1 = BN_new();
    BIGNUM *tmp2 = BN_new();

    GetInteger(tmp1, e1);
    GetInteger(tmp2, e2);

    ps[0] = GetPoint(a1);
    ps[1] = GetPoint(a2);
    ms[0] = tmp1;
    ms[1] = tmp2;

    CHECK_CALL(EC_POINTs_mul(_data->group, r, _zero, 2, ps, ms, _data->ctx));

    BN_clear_free(tmp1);
    BN_clear_free(tmp2);
    return NewElement(r);
  }

  Element OpenECGroup::Inverse(const Element &a) const
  {
    EC_POINT *r = EC_POINT_dup(GetPoint(a), _data->group);
    CHECK_CALL(r);

    CHECK_CALL(EC_POINT_invert(_data->group, r, _data->ctx));
    return NewElement(r);
  }
  
  QByteArray OpenECGroup::ElementToByteArray(const Element &a) const
  {
    // Get number of bytes requires to hold point
    const unsigned int nbytes = EC_POINT_point2oct(_data->group, GetPoint(a),
      POINT_CONVERSION_COMPRESSED, NULL, 0, _data->ctx);
    QByteArray out(nbytes, 0);

    CHECK_CALL(EC_POINT_point2oct(_data->group, GetPoint(a),
      POINT_CONVERSION_COMPRESSED, (unsigned char*)out.data(), out.count(), _data->ctx));
    return out;
  }
  
  Element OpenECGroup::ElementFromByteArray(const QByteArray &bytes) const 
  { 
    EC_POINT *point = EC_POINT_new(_data->group);
    CHECK_CALL(EC_POINT_oct2point(_data->group, point, 
          (const unsigned char*)bytes.constData(), bytes.count(), _data->ctx));
    return NewElement(point);
  }

  bool OpenECGroup::IsElement(const Element &a) const 
  {
    return EC_POINT_is_on_curve(_data->group, GetPoint(a), _data->ctx);
  }

  bool OpenECGroup::IsIdentity(const Element &a) const 
  {
    return EC_POINT_is_at_infinity(_data->group, GetPoint(a));
  }

  Integer OpenECGroup::RandomExponent() const
  {
    return Integer::GetRandomInteger(1, GetOrder(), false); 
  }

  Element OpenECGroup::RandomElement() const
  {
    return Exponentiate(GetGenerator(), RandomExponent());
  }

  Element OpenECGroup::EncodeBytes(const QByteArray &in) const
  {
    /*
    * See the article 
    *  "Encoding And Decoding  of  a Message in the 
    *  Implementation of Elliptic Curve Cryptography 
    *  using Koblitz’s Method" for details on how this works.
    * 
    * k == MessageSerializationParameter defines the percentage
    * chance that we won't be able to encode a given message
    * in a given elliptic curve point. The failure probability
    * is 2^(-k).
    *
    * We can store b = log_2(p/k) bytes in every 
    * elliptic curve point, where p is the security
    * parameter (prime size) of the elliptic curve.
    *
    * For p = 2^256, k = 256, b = 224 (minus 2 padding bytes)
    */

    if(in.count() > BytesPerElement()) {
      qFatal("Failed to serialize over-sized string");
    }

    // Holds the data to be encoded plus a leading and a trailing
    // 0xFF byte
    QByteArray data;
    data.append(0xff);
    data += in;
    data.append(0xff);

    // r is an encoding of the string in a big integer
    BIGNUM *r = BN_new();
    CHECK_CALL(BN_hex2bn(&r, (const char*)data.toHex().constData()));
      
    CHECK_CALL(BN_cmp(r, _p) < 0);

    EC_POINT *point = EC_POINT_new(_data->group);

    // Shift r left by one byte and then flip the
    // bits in the last byte until we get a valid point
    CHECK_CALL(BN_lshift(r, r, 8));
    bool success = false;
    for(int i=0; i<(1<<8); i++) {
      // x = rk + i mod p
      CHECK_CALL(BN_mod_add(r, r, _one, _p, _data->ctx));

      if(EC_POINT_set_compressed_coordinates_GFp(_data->group, point, r, 1, _data->ctx)
          && EC_POINT_is_on_curve(_data->group, point, _data->ctx)) {
        success = true;
        break;
      } 
    }

    BN_clear_free(r);

    if(success) {
        return NewElement(point);
    } else {
      qFatal("Failed to find point");
      return NewElement(NULL);
    }
  }
 
  bool OpenECGroup::DecodeBytes(const Element &a, QByteArray &out) const
  {
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    if(!EC_POINT_get_affine_coordinates_GFp(_data->group, GetPoint(a), x, y, _data->ctx))
      return false;

    // shift off padding byte
    CHECK_CALL(BN_rshift(x, x, 8));
   
    QByteArray data(BN_num_bytes(x), 0);
    CHECK_CALL(BN_bn2bin(x, (unsigned char*)data.data()));

    if(data.count() < 2) {
      qWarning() << "Data is too short";
      return false;
    }

    const unsigned char c = 0xff;
    const unsigned char d0 = data[0];
    const unsigned char dlast = data[data.count()-1];
    if((d0 != c) || (dlast != c)) {
      qWarning() << "Data has improper padding:" << data.toHex();
      return false;
    }

    out = data.mid(1, data.count()-2);

    BN_clear_free(x);
    BN_clear_free(y);

    return true;
  }

  bool OpenECGroup::IsProbablyValid() const
  {
    return EC_GROUP_check(_data->group, _data->ctx);
  }

  QByteArray OpenECGroup::GetByteArray() const
  {
    QByteArray p(BN_num_bytes(_p), 0);
    QByteArray a(BN_num_bytes(_a), 0);
    QByteArray b(BN_num_bytes(_b), 0);
    QByteArray gx(BN_num_bytes(_gx), 0);
    
    CHECK_CALL(BN_bn2bin(_p, (unsigned char*)p.data()));
    CHECK_CALL(BN_bn2bin(_a, (unsigned char*)a.data()));
    CHECK_CALL(BN_bn2bin(_b, (unsigned char*)b.data()));
    CHECK_CALL(BN_bn2bin(_gx, (unsigned char*)gx.data()));

    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);

    stream << p << a << b << gx;

    return out;
  }

  void OpenECGroup::GetCoordinates(const Element &a, Integer &x_out, Integer &y_out) const
  {
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    CHECK_CALL(EC_POINT_get_affine_coordinates_GFp(_data->group, GetPoint(a), x, y, _data->ctx));

    char *x_char = BN_bn2hex(x);
    char *y_char = BN_bn2hex(y);

    x_out = Integer("0x" + QByteArray(x_char));
    y_out = Integer("0x" + QByteArray(y_char));
    
    OPENSSL_free(x_char);
    OPENSSL_free(y_char);

    BN_clear_free(x);
    BN_clear_free(y);
  }

  int OpenECGroup::FastModMul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b) const
  {
    BIGNUM *tmp0 = BN_new();
    BIGNUM *tmp1 = BN_new();

    // Convert a and b to montgomery rep mod p
    CHECK_CALL(BN_to_montgomery(tmp0, a, _data->mont, _data->ctx));
    CHECK_CALL(BN_to_montgomery(tmp1, b, _data->mont, _data->ctx));

    // tmp = a*b
    CHECK_CALL(BN_mod_mul_montgomery(tmp0, tmp0, tmp1, _data->mont, _data->ctx));

    int ret = BN_from_montgomery(r, tmp0, _data->mont, _data->ctx);

    BN_clear_free(tmp0);
    BN_clear_free(tmp1);

    return ret;
  }

  void OpenECGroup::GetInteger(BIGNUM *ret, const Integer &i) 
  {
    CHECK_CALL(ret);
    const QByteArray data = i.GetByteArray();
    CHECK_CALL(BN_bin2bn((const unsigned char*)data.constData(), data.count(), ret));
  }
  
  Integer OpenECGroup::GetCppInteger(const BIGNUM *a) 
  {
    CHECK_CALL(a);
    QByteArray data(BN_num_bytes(a), 0);
    CHECK_CALL(BN_bn2bin(a, (unsigned char*)data.data()));

    return Integer(data);
  }

  EC_POINT *OpenECGroup::GetPoint(const Element &e) 
  {
    return OpenECElementData::GetPoint(e.GetData());
  }

  Element OpenECGroup::ElementFromCoordinates(const Integer &x_in, const Integer &y_in) const
  {
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();

    GetInteger(x, x_in);
    GetInteger(y, y_in);

    EC_POINT *point = EC_POINT_new(_data->group);

    CHECK_CALL(EC_POINT_set_affine_coordinates_GFp(_data->group, 
          point, x, y, _data->ctx));

    BN_clear_free(x);
    BN_clear_free(y);

    return NewElement(point);
  }

}
}
}
