/*
    File        : encryption.cpp
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

#include "encryption.h"
#include <openssl/pem.h>

GBEGIN_DECL

namespace Encryption
{
    RSA * createRSA(unsigned char * key,int pub)
    {
        RSA *rsa= NULL;
        BIO *keybio ;
        keybio = BIO_new_mem_buf(key, -1);
        if (keybio==NULL)
        {
            printf( "Failed to create key BIO");
            return 0;
        }
        if(pub)
        {
            rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
        }
        else
        {
            rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
        }
        if(rsa == NULL)
        {
            printf( "Failed to create RSA");
        }

        return rsa;
    }

    gerror_t encryption_create(encryption_t*& out)
    {
        if(out != nullptr)
            return GERROR_BADARGS;

        if(EVP_get_cipherbyname("aes-256-cbc") == NULL)
            OpenSSL_add_all_algorithms();

        out = (encryption_t*) malloc(sizeof(encryption_t));
        out->keypair = RSA_generate_key(2048, RSA_F4, 0, 0);

        if(!out->keypair)
        {
            free(out);
            out = nullptr;
            return GERROR_ENCRYPT_GENERATE;
        }

        return GERROR_NONE;
    }

    gerror_t encryption_destroy(encryption_t* in)
    {
        if(!in)
            return GERROR_BADARGS;

        RSA_free(in->keypair);
        free(in);
        return GERROR_NONE;
    }

    int crypt(encryption_t* rsa, unsigned char* to, unsigned char* from, size_t flen)
    {
        // Crypt from private key
        int result = RSA_private_encrypt(flen, from, to, rsa->keypair, RSA_PKCS1_PADDING);
        return result;
    }

    int decrypt(buffer_t& pubkey, unsigned char* to, unsigned char* from, size_t flen)
    {
        RSA* rsa   = createRSA(pubkey.buf, 1);
        int result = RSA_public_decrypt(flen, from, to, rsa, RSA_PKCS1_PADDING);
        return result;
    }

    gerror_t encryption_get_publickey(encryption_t* enc, buffer_t*& out)
    {
        if(!enc || !out)
            return GERROR_BADARGS;

        int err = GERROR_NONE;
        biobox_t bio = { nullptr };

#ifdef GULTRA_DEBUG
        std::cout << "[Encryption] Creating BIO buffer." << std::endl;
#endif // GULTRA_DEBUG

        err = bio_create_newbuffer(&bio);
        if(err != GERROR_NONE)
        {
#ifdef GULTRA_DEBUG
            std::cout << "[Encryption] Error creating BIO buffer : '" << gerror_to_string(err) << "'." << std::endl;
#endif // GULTRA_DEBUG
            return err;
        }

#ifdef GULTRA_DEBUG
        std::cout << "[Encryption] Reading RSA PubKey." << std::endl;
#endif // GULTRA_DEBUG

        int ret = PEM_write_bio_RSA_PUBKEY(bio.bio, enc->keypair);
        if(!ret)
        {
            bio_destroy(&bio);
            return GERROR_ENCRYPT_WRITE;
        }



        bio_read_all(&bio, out);
        bio_destroy(&bio);

        return GERROR_NONE;
    }

    gerror_t bio_create_newbuffer(biobox_t* bio)
    {
        if(!bio)
            return GERROR_BADARGS;

        if(bio->bio)
            bio_destroy(bio);

        bio->bio      = nullptr;
        bio->buf.size = 0;

        bio->bio = BIO_new(BIO_s_mem());
        if(!bio->bio)
            return GERROR_ENCRYPT_BIO;

        return GERROR_NONE;
    }

    gerror_t bio_destroy(biobox_t* bio)
    {
        if(!bio)
            return GERROR_BADARGS;

        if(!(bio->bio))
            return GERROR_NONE;

        BIO_free(bio->bio);

        bio->bio      = nullptr;
        bio->buf.size = 0;

        return GERROR_NONE;
    }

    gerror_t bio_read_all(biobox_t* bio, buffer_t* out)
    {
        if(!bio || !(bio->bio) || !out)
            return GERROR_BADARGS;

        out->size = BIO_ctrl_pending(bio->bio);
        if (BIO_read(bio->bio, (void*) out->buf, out->size) < 0) {
            out->size = 0;
            return GERROR_ENCRYPT_BIOREAD;
        }

        return GERROR_NONE;
    }
}

GEND_DECL
