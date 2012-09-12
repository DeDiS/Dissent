#ifndef DISSENT_CRYPTO_OPEN_INTEGER_DATA_H_GUARD
#define DISSENT_CRYPTO_OPEN_INTEGER_DATA_H_GUARD

#include <openssl/bn.h>
#include <string>

#include <QSharedData>
#include <QByteArray>
#include "IntegerData.hpp"
#include "Integer.hpp"

#ifndef CHECK_CALL
#define CHECK_CALL(a) do { \
  if(!(a)) { \
    qWarning() << "File:" << __FILE__ << "Line:" << __LINE__ << (#a); \
    qFatal("Error"); \
  } \
  } while(false);
#endif

namespace Dissent {
namespace Crypto {
  /**
   * "Big" OpenSSL IntegerData wrapper
   */

  static BN_CTX *SharedCtx = NULL;
  class OpenIntegerData : public IntegerData {

    public:

      /**
       * Construct using an int
       * @param value the int value
       */
      explicit OpenIntegerData(int value = 0)
      {
        CHECK_CALL(_bignum = BN_new());
        CHECK_CALL(BN_set_word(_bignum, value));
      }

      /**
       * Construct using an byte array
       * @param value the byte array
       */
      explicit OpenIntegerData(const QByteArray &byte_array) 
      {
        CHECK_CALL(_bignum = BN_new());
        CHECK_CALL(BN_bin2bn((unsigned const char*)byte_array.constData(),
              byte_array.count(), _bignum));
      }

      /**
       * Construct using a base64 string
       * @param value the string
       */
      explicit OpenIntegerData(const QString &string)
      {
        QByteArray byte_array = FromBase64(string);
        CHECK_CALL(_bignum = BN_new());
        CHECK_CALL(BN_bin2bn((const unsigned char*)byte_array.constData(), 
              byte_array.count(), _bignum));
      }

      /**
       * Construct using allocated BIGNUM
       * @param bn the BIGNUM*
       */
      explicit OpenIntegerData(BIGNUM *bn) : _bignum(bn)
      {}

      /**
       * returns a random integer data
       * @param bit_count the amount of bits in the integer
       * @param prime if the integer should be prime 
       */
      static OpenIntegerData *GetRandomInteger(int bit_count, bool prime)
      {
        BIGNUM *bn;
        CHECK_CALL(bn = BN_new());

        if(prime) {
          CHECK_CALL(BN_generate_prime(bn, bit_count, false, NULL, NULL, NULL, NULL));
        } else {
          CHECK_CALL(BN_rand(bn, bit_count, false, false));
        }
        return new OpenIntegerData(bn);
      }

      /**
       * returns a random integer data
       * @param min smallest number
       * @param max largest number
       * @param prime if the integer should be prime 
       */
      static OpenIntegerData *GetRandomInteger(const IntegerData *min,
          const IntegerData *max, bool prime)
      {
        BIGNUM *bn;
        CHECK_CALL(bn = BN_new());

        BIGNUM *diff;
        CHECK_CALL(diff = BN_new());
        CHECK_CALL(BN_sub(diff, GetBignum(max), GetBignum(min)));

        if(prime) {
          while(true) {
            CHECK_CALL(BN_rand_range(bn, diff));
            CHECK_CALL(BN_add(bn, bn, GetBignum(min)));
            if(BN_is_prime(bn, 80, NULL, GetContext(), NULL)) break;
          }
        } else {
          CHECK_CALL(BN_rand_range(bn, diff));
          CHECK_CALL(BN_add(bn, bn, GetBignum(min)));
        }

        BN_clear_free(diff);

        return new OpenIntegerData(bn);
      }

      /**
       * Destructor
       */
      virtual ~OpenIntegerData() 
      {
        BN_clear_free(_bignum); 
      }

      /**
       * Add operator, produces a new Integer
       * @param other the Integer to add
       */
      virtual IntegerData *Add(const IntegerData *other) const
      {
        BIGNUM *bn;
        CHECK_CALL(bn = BN_new());

        CHECK_CALL(BN_add(bn, _bignum, GetBignum(other)));
        return new OpenIntegerData(bn);
      }

      /**
       * Subtraction operator, produces a new Integer
       * @param other the Integer to subtract (subtrahend)
       */
      virtual IntegerData *Subtract(const IntegerData *other) const
      {
        BIGNUM *bn;
        CHECK_CALL(bn = BN_new());

        CHECK_CALL(BN_sub(bn, _bignum, GetBignum(other)));
        return new OpenIntegerData(bn);
      }

      /**
       * Subtraction operator, produces a new Integer
       * @param multiplicand the Integer to multiply this
       */
      virtual IntegerData *Multiply(const IntegerData *multiplicand) const
      {
        BIGNUM *bn;
        CHECK_CALL(bn = BN_new());

        CHECK_CALL(BN_mul(bn, _bignum, GetBignum(multiplicand), GetContext()));
        return new OpenIntegerData(bn);
      }

      /**
       * Division operator, produces a new Integer
       * @param divisor the Integer to divide into this
       */
      virtual IntegerData *Divide(const IntegerData *divisor) const
      {
        BIGNUM *bn;
        CHECK_CALL(bn = BN_new());

        CHECK_CALL(BN_div(bn, NULL, _bignum, GetBignum(divisor), GetContext()));
        return new OpenIntegerData(bn);
      }

      /**
       * Exponentiating operator
       * @param pow raise this to other
       */
      virtual IntegerData *Pow(const IntegerData *pow,
          const IntegerData *mod) const
      {
        Q_ASSERT(!BN_is_negative(_bignum));
        Q_ASSERT(!BN_is_negative(GetBignum(pow)));
        Q_ASSERT(!BN_is_negative(GetBignum(mod)));

        BIGNUM *bn;
        CHECK_CALL(bn = BN_new());

        if(BN_is_negative(GetBignum(pow))) qFatal("Cannot handle negative exponents");
        CHECK_CALL(BN_mod_exp(bn, _bignum, GetBignum(pow), GetBignum(mod), GetContext()));

        return new OpenIntegerData(bn);
      }

      /**
       * Cascade exponentiation modulo n
       * For integer n, compute ((x1^e1 * x2^e2) mod n)
       * This can be much faster than the naive way.
       * @param x1 first base
       * @param e1 first exponent
       * @param x2 second base
       * @param e2 second exponent
       */
      virtual IntegerData *PowCascade(const IntegerData *x1, const IntegerData *e1,
          const IntegerData *x2, const IntegerData *e2) const 
      {
        Q_ASSERT(!BN_is_negative(_bignum));
        Q_ASSERT(!BN_is_negative(GetBignum(x1)));
        Q_ASSERT(!BN_is_negative(GetBignum(e1)));
        Q_ASSERT(!BN_is_negative(GetBignum(x2)));
        Q_ASSERT(!BN_is_negative(GetBignum(e2)));

        BIGNUM *bn;
        BIGNUM *bn2;
        CHECK_CALL(bn = BN_new());
        CHECK_CALL(bn2 = BN_new());

        CHECK_CALL(BN_mod_exp(bn, GetBignum(x1), GetBignum(e1), _bignum, GetContext()));
        CHECK_CALL(BN_mod_exp(bn2, GetBignum(x2), GetBignum(e2), _bignum, GetContext()));
        CHECK_CALL(BN_mod_mul(bn, bn, bn2, _bignum, GetContext()));
        BN_clear_free(bn2);
        return new OpenIntegerData(bn);
      }

      /**
       * Multiplication mod operator
       * @param other number to multiply
       * @param mod modulus
       */
      virtual IntegerData *MultiplyMod(const IntegerData *other,
          const IntegerData *mod) const
      {
        Q_ASSERT(!BN_is_negative(GetBignum(mod)));

        BIGNUM *bn;
        CHECK_CALL(bn = BN_new());

        CHECK_CALL(BN_mod_mul(bn, _bignum, GetBignum(other), GetBignum(mod), GetContext()));
        return new OpenIntegerData(bn);
      }

      /**
       * Modular multiplicative inverse
       * @param mod the modulus
       */
      virtual IntegerData *ModInverse(const IntegerData *mod) const
      {
        BIGNUM *bn;
        CHECK_CALL(bn = BN_new());

        Q_ASSERT(!BN_is_negative(GetBignum(mod)));
        Q_ASSERT(!BN_is_negative(_bignum));

        CHECK_CALL(BN_mod_inverse(bn, _bignum, GetBignum(mod), GetContext()));
        return new OpenIntegerData(bn);
      }

      /**
       * Return a mod m
       * @param mod the modulus
       */
      virtual IntegerData *Modulo(const IntegerData *modulus) const 
      {
        Q_ASSERT(!BN_is_negative(GetBignum(modulus)));

        BIGNUM *bn;
        CHECK_CALL(bn = BN_new());

        CHECK_CALL(BN_nnmod(bn, _bignum, GetBignum(modulus), GetContext()));
        return new OpenIntegerData(bn);
      }

      /**
       * Assignment operator
       * @param other the IntegerData to use for setting
       */
      virtual void Set(const IntegerData *other)
      {
        CHECK_CALL(BN_copy(_bignum, GetBignum(other)));
      }

      /**
       * Add operator, adds to current
       * @param other the IntegerData to add
       */
      virtual void operator+=(const IntegerData *other)
      {
        CHECK_CALL(BN_add(_bignum, _bignum, GetBignum(other)));
      }

      /**
       * Subtraction operator, subtracts from the current
       * @param other the IntegerData to subtract
       */
      virtual void operator-=(const IntegerData *other)
      {
        CHECK_CALL(BN_sub(_bignum, _bignum, GetBignum(other)));
      }

      /**
       * Equality operator
       * @param other the IntegerData to compare
       */
      virtual bool operator==(const IntegerData *other) const
      {
        return !BN_cmp(_bignum, GetBignum(other));
      }

      /**
       * Not equal operator
       * @param other the IntegerData to compare
       */
      virtual bool operator!=(const IntegerData *other) const
      {
        return (bool)BN_cmp(_bignum, GetBignum(other));
      }

      /**
       * Greater than
       * @param other the IntegerData to compare
       */
      virtual bool operator>(const IntegerData *other) const
      {
        return (BN_cmp(_bignum, GetBignum(other)) == 1);
      }

      /**
       * Greater than or equal
       * @param other the IntegerData to compare
       */
      virtual bool operator>=(const IntegerData *other) const
      {
        return (BN_cmp(_bignum, GetBignum(other)) > -1);
      }

      /**
       * Less than
       * @param other the IntegerData to compare
       */
      virtual bool operator<(const IntegerData *other) const
      {
        return (BN_cmp(_bignum, GetBignum(other)) == -1);
      }

      /**
       * Less than or equal
       * @param other the IntegerData to compare
       */
      virtual bool operator<=(const IntegerData *other) const
      {
        return (BN_cmp(_bignum, GetBignum(other)) < 1);
      }

      /**
       * Returns the integer's count in bits
       */
      virtual int GetBitCount() const
      {
        return 8*BN_num_bytes(_bignum);
      }

      /**
       * Returns the integer's count in bytes
       */
      virtual int GetByteCount() const
      {
        return BN_num_bytes(_bignum);
      }

      /**
       * Returns int32 rep
       */
      virtual int GetInt32() const
      {
        return (int)BN_get_word(_bignum);
      }

      /**
       * Returns the internal BIGNUM*
       */
      inline static BIGNUM* GetBignum(const IntegerData *data)
      {
        const OpenIntegerData *pcdata =
          dynamic_cast<const OpenIntegerData *>(data);
        if(pcdata) {
          return pcdata->_bignum;
        }

        return NULL;
      }

    protected:
      virtual void GenerateByteArray()
      {
        QByteArray byte_array(BN_num_bytes(_bignum), 0);
        if(BN_bn2bin(_bignum, (unsigned char*)byte_array.data())) { 
          SetByteArray(byte_array);
        } else {
          SetByteArray(QByteArray());
        }
      }

      virtual void GenerateCanonicalRep()
      {
        QByteArray byte_array(BN_num_bytes(_bignum), 0);
        CHECK_CALL(BN_bn2bin(_bignum, (unsigned char*)byte_array.data()));
        SetCanonicalRep(byte_array);
      }

    private:
      
      static BN_CTX* GetContext()
      {
        if(SharedCtx == NULL) {
          CHECK_CALL(SharedCtx = BN_CTX_new());
        }

        return SharedCtx;
      }

      BIGNUM *_bignum;

  };
}
}

#endif
