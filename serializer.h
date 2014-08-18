/*
    This file is part of the GangTella project
*/
#ifndef __SERIALIZER_H__
#define __SERIALIZER_H__

#include "prerequesites.h"

GBEGIN_DECL

/*

    How net serialization is handled in GangTella :
    **********************************************

    Every simple types has a _nt equivalent wich is a union
    with global bytes.

*/

typedef union {
    uint8_t data;
    byte_t bytes[1];
} uint8_nt;

typedef union {
    uint16_t data;
    byte_t  bytes[2];
} uint16_nt;

typedef union {
    uint32_t data;
    byte_t  bytes[4];
} uint32_nt;

typedef union {
    float    data;
    uint32_t i;
    byte_t   bytes[4];
    struct
    {
        uint32_t mantissa : 23;
        uint32_t exponent : 8;
        uint32_t sign : 1;
    } parts;
} float_nt;

typedef union {
    uint64_t data;
    byte_t  bytes[8];
} uint64_nt;

template<class To, class From>
To serialize(const From& src) {
    cout << "[Serializer] No implementation found for template<" << typeid(To).name() << ", " << typeid(From).name() << ">." << endl;
}

template <> uint8_nt  serialize(const uint8_nt& );
template <> uint16_nt serialize(const uint16_nt&);
template <> uint32_nt serialize(const uint32_nt&);
template <> float_nt  serialize(const float_nt& );
template <> uint64_nt serialize(const uint64_nt&);

template<class To, class From>
To deserialize(const From& src) {
    cout << "[Deserializer] No implementation found for template<" << typeid(To).name() << ", " << typeid(From).name() << ">." << endl;
}

template <> uint8_nt  deserialize(const uint8_nt&);
template <> uint16_nt deserialize(const uint16_nt&);
template <> uint32_nt deserialize(const uint32_nt&);
template <> float_nt  deserialize(const float_nt& );
template <> uint64_nt deserialize(const uint64_nt&);

GEND_DECL

#endif // __SERIALIZER_H__




