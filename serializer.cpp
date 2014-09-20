/*
    This file is part of the GangTella project
*/

#include "serializer.h"

GBEGIN_DECL

template <> uint8_nt  serialize(const uint8_nt& src)
{
    return src;
}

template <> uint8_nt  deserialize(const uint8_nt& src)
{
    return src;
}

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

template <> size_nt serialize(const size_nt& src)
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

GEND_DECL


