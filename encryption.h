/*
    File        : encryption.h
    Description : Encryption/Decryption related functions.
*/

/*
    GangTella Project
    Copyright (C) 2014  Luk2010

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef __ENCRYPTION_H__
#define __ENCRYPTION_H__

#include "prerequesites.h"

GBEGIN_DECL

namespace Encryption
{
    // This encryption module is from
    // http://stackoverflow.com/questions/5367991/c-openssl-export-private-key

    // A structure holding the RSA key pair.
    typedef struct {
        RSA* keypair;
    } encryption_t;

    // The BIO structure with a buffer integrated.
    typedef struct {
        BIO*     bio;
        buffer_t buf;
    } biobox_t;

    gerror_t Init();
    gerror_t encryption_create(encryption_t*& out);
    gerror_t encryption_destroy(encryption_t* in);
    int      crypt(encryption_t* rsa, unsigned char* to, unsigned char* from, size_t flen);
    int      decrypt(buffer_t& pubkey, unsigned char* to, unsigned char* from, size_t flen);

    // Return in a buffer_t the public key.
    gerror_t encryption_get_publickey(encryption_t* enc, buffer_t*& out);

    gerror_t bio_create_newbuffer(biobox_t* bio);
    gerror_t bio_destroy(biobox_t* bio);
    gerror_t bio_read_all(biobox_t* bio, buffer_t* out);
    
    gerror_t user_create_keypass(std::string& outkey, std::string& outiv, const char* passwd, size_t passwdsz);
	bool	 user_check_password(std::string inkey, std::string iniv, const char* passwd, size_t passwdsz);
    
    /* Encrypt / Decrypt with AES 256.
     Adapted from : http://stackoverflow.com/questions/24856303/openssl-aes-256-cbc-via-evp-api-in-c
    */
    gerror_t AESCrypt(unsigned char* inbuf, uint32_t inbufsize, unsigned char*& outbuf, int* outlen, std::string& key, std::string& iv, bool encrypt);
    
    gerror_t aes256_file(bool should_encrypt, FILE* ifp, FILE* ofp, unsigned char* ckey, unsigned char* ivec);
}

typedef Encryption::encryption_t crypt_t;

gerror_t encryption_init();

GEND_DECL

#endif // __ENCRYPTION_H__
