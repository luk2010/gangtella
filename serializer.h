/*
    This file is part of the GangTella project
*/
#ifndef __SERIALIZER_H__
#define __SERIALIZER_H__

#include "prerequesites.h"

GBEGIN_DECL

/*

    Serialization module for GangTella. 

 Just a simple wrapper of simple types. This does not convert 
 data to text as much serializer does. It swap the bytes depending on the
 destination platform. 
 
 Serialize convert from your platform to BigEndian. 
 Deserialize convert from BigEndian to your platform.

*/

template<class To, class From>
To serialize(const From& src) {
    cout << "[Serializer] No implementation found for template<" << typeid(To).name() << ", " << typeid(From).name() << ">." << endl;
}

template <> uint8_t  serialize(const uint8_t& );
template <> uint16_t  serialize(const uint16_t& );
template <> uint32_t serialize(const uint32_t&);
template <> float  serialize(const float& );
template <> size_t   serialize(const size_t&);
template <> uint64_t serialize(const uint64_t&);

template<class To, class From>
To deserialize(const From& src) {
    cout << "[Deserializer] No implementation found for template<" << typeid(To).name() << ", " << typeid(From).name() << ">." << endl;
}

template <> uint8_t  deserialize(const uint8_t& );
template <> uint16_t  deserialize(const uint16_t& );
template <> uint32_t deserialize(const uint32_t&);
template <> float  deserialize(const float& );
template <> size_t   deserialize(const size_t&);
template <> uint64_t deserialize(const uint64_t&);

GEND_DECL

#endif // __SERIALIZER_H__




