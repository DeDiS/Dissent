#ifndef DISSENT_CRYPTO_ABSTRACT_GROUP_OPEN_EC_ELEMENT_DATA_H_GUARD
#define DISSENT_CRYPTO_ABSTRACT_GROUP_OPEN_EC_ELEMENT_DATA_H_GUARD

#include <openssl/ec.h>
#include "ElementData.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  /**
   * This is a point on an elliptic curve
   * implemented using OpenSSL
   */
  class OpenECElementData : public ElementData {

    public:

      /**
       * Constructor -- We are responsible for freeing
       * the point, but NOT the group or ctx.
       * @param point elliptic curve point
       * @param group elliptic curve group
       * @param ctx BIGNUM context
       */
      OpenECElementData(EC_POINT *point, EC_GROUP *group, BN_CTX *ctx) : 
        _point(point), _group(group), _ctx(ctx) {}

      /**
       * Destructor
       */
      virtual ~OpenECElementData() 
      {
        EC_POINT_clear_free(_point); 
      }

      /**
       * Equality operator
       * @param other the ElementData to compare
       */
      virtual bool operator==(const ElementData *other) const
      {
        return !EC_POINT_cmp(_group, _point, GetPoint(other), _ctx);
      }

      /**
       * Get the point associated with this ElementData
       * @param data data element to query
       */
      inline static EC_POINT *GetPoint(const ElementData *data)
      {
        const OpenECElementData *elmdata =
          dynamic_cast<const OpenECElementData*>(data);
        if(elmdata) {
          return elmdata->_point;
        } else {
          qFatal("Invalid cast (OpenECElementData)");
        }

        return NULL;
      }

    private:

      EC_POINT *_point;
      EC_GROUP *_group;
      BN_CTX *_ctx;
  };

}
}
}

#endif
