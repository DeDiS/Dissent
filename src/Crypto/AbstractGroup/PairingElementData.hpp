#ifndef DISSENT_CRYPTO_ABSTRACT_GROUP_PAIRING_ELEMENT_DATA_H_GUARD
#define DISSENT_CRYPTO_ABSTRACT_GROUP_PAIRING_ELEMENT_DATA_H_GUARD

#include <PBC.h>
#include <QByteArray>
#include <QSharedPointer>
#include "ElementData.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  template<class T>
  class PairingElementData : public ElementData {

    public:

      PairingElementData(T element) :
        _element(element) {}

      /**
       * Destructor
       */
      virtual ~PairingElementData() {}

      /**
       * Equality operator
       * @param other the ElementData to compare
       */
      virtual bool operator==(const ElementData *other) const
      {
        T e = GetElement(other);
        return (_element == e);
      }

      /**
       * Get the point associated with this ElementData
       * @param data data element to query
       */
      inline static T GetElement(const ElementData *data) 
      {
        const PairingElementData<T> *elmdata = 
          dynamic_cast<const PairingElementData<T>*>(data);
        if(elmdata) {
          Q_ASSERT(elmdata->_element.isElementPresent());
          //elmdata->_element.dump(stderr, "element: ", 10);
          return elmdata->_element;
        } else {
          qFatal("Invalid cast (PairingElementData)");
        }

        return T();
      }

    private: 

      T _element;

  };

}
}
}

#endif
