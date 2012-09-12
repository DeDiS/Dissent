#ifndef DISSENT_CRYPTO_ABSTRACT_GROUP_OPEN_EC_GROUP_H_GUARD
#define DISSENT_CRYPTO_ABSTRACT_GROUP_OPEN_EC_GROUP_H_GUARD

#include <openssl/ec.h>
#include <QSharedPointer>

#include "AbstractGroup.hpp"
#include "OpenECElementData.hpp"

#ifndef CHECK_CALL
#define CHECK_CALL(a) do { if(!(a)) {qWarning() << "File:" << __FILE__ << "Line:" << __LINE__ << #a; \
  qFatal("Error"); } } while(false);
#endif 

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  /**
   * This class represents an elliptic curve modulo
   * a prime. The curves take the form:
   *   y^2 = x^3 + ax + b (mod p)
   * This class uses an OpenSSL implementation.
   */
  class OpenECGroup : public AbstractGroup {

    public:
      /**
       * Constructor: OpenECGroup will free all 
       * of these BIGNUMs on exit.
       * @param p must be a prime 
       * @param q order of the field
       * @param a linear coefficient of curve
       * @param b constant term of curve
       * @param gx x-coordinate of generating point
       * @param gy y-coordinate of generating point
       * @param is_nist_curve curve is a NIST-recommended curve
       *        (allows some optimizations)
       */
      OpenECGroup(BIGNUM *p, BIGNUM *q,
          BIGNUM *a, BIGNUM *b, BIGNUM *gx, BIGNUM *gy, 
          bool is_nist_curve);

      /**
       * A convenience constructor for above, using genertic Integer
       * instead of BIGNUM*
       */
      static QSharedPointer<OpenECGroup> NewGroup(const Integer &p, 
          const Integer &q, const Integer &a, 
          const Integer &b, const Integer &gx, 
          const Integer &gy, bool is_nist_curve);

      /**
       * Get a fixed group using the RFC 5903 256-bit curve
       * (is a NIST curve)
       */
      static QSharedPointer<OpenECGroup> ProductionFixed();

      /**
       * Destructor
       */
      virtual ~OpenECGroup();

      /**
       * Add two elliptic curve points
       * @param a first operand 
       * @param b second operand 
       */
      virtual Element Multiply(const Element &a, const Element &b) const;

      /**
       * Multiply an EC point by scalar exp
       * @param a base
       * @param exp exponent
       */
      virtual Element Exponentiate(const Element &a, const Integer &exp) const;

      /**
       * Compute (e1a1 + e2a2). Generally this can be done much faster
       * than two separate operations.
       * @param a1 base 1
       * @param e1 exponent 1
       * @param a2 base 2
       * @param e2 exponent 2
       */
      virtual Element CascadeExponentiate(const Element &a1, const Integer &e1,
          const Element &a2, const Integer &e2) const;

      /**
       * Compute b such that a+b = O (identity)
       * @param a element to invert
       */
      virtual Element Inverse(const Element &a) const;

      /**
       * Serialize the element as a QByteArray
       * @param a element to serialize 
       */
      virtual QByteArray ElementToByteArray(const Element &a) const;

      /**
       * Unserialize an element from a QByteArray
       * @param bytes the byte array to unserialize
       */
      virtual Element ElementFromByteArray(const QByteArray &bytes) const;

      /**
       * Return true if a is an element of the group -- i.e., if 
       * a is a point on the curve
       * @param a element to test
       */
      virtual bool IsElement(const Element &a) const;

      /**
       * Return true if a == O (identity)
       * @param a element to test
       */
      virtual bool IsIdentity(const Element &a) const;

      /**
       * Return an integer in [0, q)
       */
      virtual Integer RandomExponent() const;

      /**
       * Return a random point on the curve
       */
      virtual Element RandomElement() const;

      /**
       * Return the group generating point (g)
       */
      inline virtual Element GetGenerator() const 
      { 
        EC_POINT *g = EC_POINT_dup(_generator, _data->group);
        CHECK_CALL(g);
        return NewElement(g);
      }
      
      /**
       * Return the group order (q)
       */
      inline virtual Integer GetOrder() const 
      {
        return GetCppInteger(_q);
      }

      /**
       * Return the group identity element O
       */
      inline virtual Element GetIdentity() const
      {
        EC_POINT *i = EC_POINT_new(_data->group);
        CHECK_CALL(i);
        CHECK_CALL(EC_POINT_set_to_infinity(_data->group, i));
        return NewElement(i);
      }

      /**
       * Return the number of bytes that can be
       * encoded in a single group element
       */
      inline virtual int BytesPerElement() const {
        // Bytes in field minus bytes in parameter k
        // minus two padding bytes and one byte to 
        // make x a point
        return (_field_bytes - 3);
      }

      /**
       * Encode ByteArray into group element. Fails if the 
       * byte array is too long -- make sure that the byte
       * array is shorter than BytesPerElement()
       * @param input QByteArray to encode
       */
      virtual Element EncodeBytes(const QByteArray &in) const;

      /**
       * Decode a group element into a QByteArray
       * @param a the element containing the string
       * @param out reference in which to return string
       * @returns true if everything is okay, false if cannot read
       *          string
       */
      virtual bool DecodeBytes(const Element &a, QByteArray &out) const;

      /**
       * Check if the group is probably valid. It's hard to
       * check in general, so this is just a "best effort" test.
       */
      virtual bool IsProbablyValid() const;

      /**
       * Get a byte array representation of the group
       */
      virtual QByteArray GetByteArray() const;

      /**
       * Get (x,y) coordinates of an element point
       * @param a Element from which to get points
       * @param x return x value
       * @param y return y value
       */
      void GetCoordinates(const Element &a, Integer &x, Integer &y) const;

      /**
       * Get a point from (x,y) coordinates
       * @param x coordinate
       * @param y coordinate
       */
      Element ElementFromCoordinates(const Integer &x, const Integer &y) const;

      /**
       * Return true if element is a generator
       */
      virtual inline bool IsGenerator(const Element &a) const { 
        return IsElement(a) && !IsIdentity(a);
      }

      /**
       * Return a printable representation of the group
       */
      virtual inline QString ToString() const 
      {
        return QString("OpenECGroup");
      }

      /**
       * Generally, the number of bits in the modulus
       */ 
      inline int GetSecurityParameter() const {
        return (BN_num_bytes(_p) * 8);
      }

    private:

      inline Element NewElement(EC_POINT *e) const 
      {
        return Element(new OpenECElementData(e, _data->group, _data->ctx)); 
      }

      /**
       * Create a new BIGNUM from Integer. ret
       * must already have been initialized with BN_new()
       */
      static void GetInteger(BIGNUM *ret, const Integer &i);
      static Integer GetCppInteger(const BIGNUM *a);
      static EC_POINT *GetPoint(const Element &e);

      /**
       * Fast multiplication mod p using stored BN_MONT_CTX
       */
      int FastModMul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b) const;

      /**
       * These are members of the class that will change
       */
      class MutableData {
        public:
          MutableData(bool is_nist_curve) :
            ctx(BN_CTX_new()),
            mont(BN_MONT_CTX_new()),
            group(EC_GROUP_new(
                  is_nist_curve ? EC_GFp_nist_method() : EC_GFp_mont_method())) 
          {}

          ~MutableData() {
            EC_GROUP_clear_free(group);
            BN_MONT_CTX_free(mont);
            BN_CTX_free(ctx);
          }

          BN_CTX *ctx;
          BN_MONT_CTX *mont;
          EC_GROUP *group;
      };

      BIGNUM *_p;
      BIGNUM *_q;
      BIGNUM *_a;
      BIGNUM *_b;
      BIGNUM *_gx;
      BIGNUM *_gy;

      BIGNUM *_zero;
      BIGNUM *_one;

      MutableData *_data;
      EC_POINT *_generator;

      Integer _order;

      /** Serialization parameters */
      const int _field_bytes;

  };

}
}
}

#endif
