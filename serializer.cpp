/*
    This file is part of the GangTella project
*/

#include "serializer.h"

GBEGIN_DECL

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
    size_t data;
    byte_t bytes[sizeof(size_t)];
} size_nt;

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
    uint64_t  data;
    uint32_nt parts[2];
} uint64_nt;

template <> uint8_nt  serialize(const uint8_nt& );
template <> uint16_nt serialize(const uint16_nt&);
template <> uint32_nt serialize(const uint32_nt&);
template <> float_nt  serialize(const float_nt& );
template <> size_nt   serialize(const size_nt&);
template <> uint64_nt serialize(const uint64_nt&);

template <> uint8_nt  deserialize(const uint8_nt&);
template <> uint16_nt deserialize(const uint16_nt&);
template <> uint32_nt deserialize(const uint32_nt&);
template <> float_nt  deserialize(const float_nt& );
template <> size_nt   deserialize(const size_nt&);
template <> uint64_nt deserialize(const uint64_nt&);

/* ========================= uint8 =============================== */

template <> uint8_nt  serialize(const uint8_nt& src)
{
    return src;
}

template <> uint8_t  serialize(const uint8_t& rhs)
{
    return rhs;
}

template <> uint8_nt  deserialize(const uint8_nt& src)
{
    return src;
}

template <> uint8_t  deserialize(const uint8_t& rhs)
{
    return rhs;
}

/* ========================= uint16 =============================== */

template <> uint16_nt  serialize(const uint16_nt& rhs)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint16_nt ret;
    ret.bytes[1] = rhs.bytes[0];
    ret.bytes[0] = rhs.bytes[1];
    return ret;
#else
    return rhs;
#endif
}

template <> uint16_t  serialize(const uint16_t& rhs)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return (rhs<<8) | (rhs>>8);
#else
    return rhs;
#endif
}

template <> uint16_nt deserialize(const uint16_nt& rhs)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint16_nt ret;
    ret.bytes[1] = rhs.bytes[0];
    ret.bytes[0] = rhs.bytes[1];
    return ret;
#else
    return rhs;
#endif
}

template <> uint16_t  deserialize(const uint16_t& rhs)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return (rhs<<8) | (rhs>>8);
#else
    return rhs;
#endif
}

/* ========================= uint32 =============================== */


template <> uint32_nt serialize(const uint32_nt& src)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint32_nt ret;
    ret.bytes[0] = src.bytes[3];
    ret.bytes[1] = src.bytes[2];
    ret.bytes[2] = src.bytes[1];
    ret.bytes[3] = src.bytes[0];
    return ret;
#else
    return src;
#endif // __BYTE_ORDER
}

template <> uint32_t serialize(const uint32_t& val)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return (val<<24) | ((val<<8) & 0x00ff0000) |
		  ((val>>8) & 0x0000ff00) | (val>>24);
#else
    return val;
#endif // __BYTE_ORDER
}

template <> uint32_nt deserialize(const uint32_nt& src)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint32_nt ret;
    ret.bytes[0] = src.bytes[3];
    ret.bytes[1] = src.bytes[2];
    ret.bytes[2] = src.bytes[1];
    ret.bytes[3] = src.bytes[0];
    return ret;
#else
    return src;
#endif // __BYTE_ORDER
}

template <> uint32_t deserialize(const uint32_t& val)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return (val<<24) | ((val<<8) & 0x00ff0000) |
		  ((val>>8) & 0x0000ff00) | (val>>24);
#else
    return val;
#endif // __BYTE_ORDER
}

/* ========================= uint64 =============================== */

template <> uint64_nt serialize(const uint64_nt& src)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint64_nt ret;
    ret.parts[0] = serialize<uint32_nt>(src.parts[1]);
    ret.parts[1] = serialize<uint32_nt>(src.parts[0]);
    return ret;
#else
    return src;
#endif // __BYTE_ORDER
}

template <> uint64_t serialize(const uint64_t& src)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint64_nt tmp; tmp.data = src;
    uint64_nt ret;
    ret.parts[0] = serialize<uint32_nt>(tmp.parts[1]);
    ret.parts[1] = serialize<uint32_nt>(tmp.parts[0]);
    return ret.data;
#else
    return src;
#endif // __BYTE_ORDER
}

template <> uint64_nt deserialize(const uint64_nt& src)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint64_nt ret;
    ret.parts[0] = serialize<uint32_nt>(src.parts[1]);
    ret.parts[1] = serialize<uint32_nt>(src.parts[0]);
    return ret;
#else
    return src;
#endif // __BYTE_ORDER
}

template <> uint64_t deserialize(const uint64_t& src)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint64_nt tmp; tmp.data = src;
    uint64_nt ret;
    ret.parts[0] = serialize<uint32_nt>(tmp.parts[1]);
    ret.parts[1] = serialize<uint32_nt>(tmp.parts[0]);
    return ret.data;
#else
    return src;
#endif // __BYTE_ORDER
}

/* ========================= float =============================== */

template <> float_nt serialize(const float_nt& src)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    float_nt ret;
    ret.bytes[0] = src.bytes[3];
    ret.bytes[1] = src.bytes[2];
    ret.bytes[2] = src.bytes[1];
    ret.bytes[3] = src.bytes[0];
    return ret;
#else
    return src;
#endif // __BYTE_ORDER
}

template <> float serialize(const float& src)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    float_nt tmp; tmp.data = src;
    float_nt ret;
    ret.bytes[0] = tmp.bytes[3];
    ret.bytes[1] = tmp.bytes[2];
    ret.bytes[2] = tmp.bytes[1];
    ret.bytes[3] = tmp.bytes[0];
    return ret.data;
#else
    return src;
#endif // __BYTE_ORDER
}

template <> float_nt deserialize(const float_nt& src)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    float_nt ret;
    ret.bytes[0] = src.bytes[3];
    ret.bytes[1] = src.bytes[2];
    ret.bytes[2] = src.bytes[1];
    ret.bytes[3] = src.bytes[0];
    return ret;
#else
    return src;
#endif // __BYTE_ORDER
}

template <> float deserialize(const float& src)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    float_nt tmp; tmp.data = src;
    float_nt ret;
    ret.bytes[0] = tmp.bytes[3];
    ret.bytes[1] = tmp.bytes[2];
    ret.bytes[2] = tmp.bytes[1];
    ret.bytes[3] = tmp.bytes[0];
    return ret.data;
#else
    return src;
#endif // __BYTE_ORDER
}

/* ========================= size_t =============================== */

#ifndef size_t

template <> size_nt serialize(const size_nt& src)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    size_nt ret;
    
    for(unsigned int i = 0; i < sizeof(size_t); ++i)
        ret.bytes[i] = src.bytes[sizeof(size_t) - (i+1)];
    
    return ret;
#else
    return src;
#endif // __BYTE_ORDER
}

template <> size_t serialize(const size_t& src)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    size_nt tmp; tmp.data = src;
    size_nt ret;
    
    for(unsigned int i = 0; i < sizeof(size_t); ++i)
        ret.bytes[i] = tmp.bytes[sizeof(size_t) - (i+1)];
    
    return ret.data;
#else
    return src;
#endif // __BYTE_ORDER
}

template <> size_nt deserialize(const size_nt& src)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    size_nt ret;
    ret.bytes[0] = src.bytes[7];
    ret.bytes[1] = src.bytes[6];
    ret.bytes[2] = src.bytes[5];
    ret.bytes[3] = src.bytes[4];
    ret.bytes[4] = src.bytes[3];
    ret.bytes[5] = src.bytes[2];
    ret.bytes[6] = src.bytes[1];
    ret.bytes[7] = src.bytes[0];
    return ret;
#else
    return src;
#endif // __BYTE_ORDER
}

template <> size_t deserialize(const size_t& src)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    size_nt tmp; tmp.data = src;
    size_nt ret;
    
    for(unsigned int i = 0; i < sizeof(size_t); ++i)
        ret.bytes[i] = tmp.bytes[sizeof(size_t) - (i+1)];
    
    return ret.data;
#else
    return src;
#endif // __BYTE_ORDER
}

#endif

GEND_DECL


