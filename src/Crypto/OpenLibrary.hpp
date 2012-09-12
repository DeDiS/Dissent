#ifndef DISSENT_CRYPTO_OPEN_LIBRARY_H_GUARD
#define DISSENT_CRYPTO_OPEN_LIBRARY_H_GUARD

#include "CppLibrary.hpp"
#include "OpenIntegerData.hpp"

namespace Dissent {
namespace Crypto {
  class OpenLibrary : public CppLibrary {
    public:

      /**
       * Returns an integer data
       */
      inline virtual IntegerData *GetIntegerData(int value)
      {
        return new OpenIntegerData(value);
      }

      /**
       * Returns an integer data
       */
      inline virtual IntegerData *GetIntegerData(const QByteArray &value)
      {
        return new OpenIntegerData(value);
      }

      /**
       * Returns an integer data
       */
      inline virtual IntegerData *GetIntegerData(const QString &value)
      {
        return new OpenIntegerData(value);
      }

      /**
       * returns a random integer data
       * @param bit_count the amount of bits in the integer
       * @param prime if the integer should be prime 
       */
      virtual IntegerData *GetRandomInteger(int bit_count, bool prime)
      {
        return OpenIntegerData::GetRandomInteger(bit_count, prime);
      }

      /**
       * returns a random integer data
       * @param min the minimum number
       * @param max the maximum number
       * @param prime should the resulting number be prime
       */
      virtual IntegerData *GetRandomInteger(const IntegerData *min,
          const IntegerData *max, bool prime)
      {
        return OpenIntegerData::GetRandomInteger(min, max, prime);
      }

  };
}
}

#endif
