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
    /** @brief Init OpenSSL algorithms stuff. */
    gerror_t Init()
    {
        ERR_load_CRYPTO_strings();
        OpenSSL_add_all_algorithms();
//      OPENSSL_config(NULL);
        return GERROR_NONE;
    }

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

        BIO_free(keybio);

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

    /** @brief Crypt data
     *  @param rsa  : RSA private key
     *  @param to   : Buffer to store data. Size of buffer must be RSA_SIZE.
     *  @param from : Buffer to read the data.
     *  @param flen : Size of buffer from. Must be inferior or equal to RSA_SIZE - 11.
    **/
    int crypt(encryption_t* rsa, unsigned char* to, unsigned char* from, size_t flen)
    {
        // Crypt from private key
        int result = RSA_private_encrypt((int) flen, from, to, rsa->keypair, RSA_PKCS1_PADDING);
        return result;
    }

    /** @brief Decrypt data
     *  @param pubkey : The public key to decrypt the data.
     *  @param to     : Buffer to hold the message digest. Size of this buffer must be
     *                  RSA_SIZE - 11.
     *  @param from   : Buffer to decrypt.
     *  @param flen   : Lenght of this buffer. It must not be superior to RSA_SIZE.
    **/
    int decrypt(buffer_t& pubkey, unsigned char* to, unsigned char* from, size_t flen)
    {
        RSA* rsa   = createRSA(pubkey.buf, 1);
        int result = RSA_public_decrypt((int) flen, from, to, rsa, RSA_PKCS1_PADDING);
        RSA_free(rsa);
        return result;
    }

    gerror_t encryption_get_publickey(encryption_t* enc, buffer_t*& out)
    {
        if(!enc || !out)
            return GERROR_BADARGS;

        GError err = GERROR_NONE;
        biobox_t bio;
        bio.bio = nullptr;
        bio.buf.size = 0;

#ifdef GULTRA_DEBUG
        cout << "[Encryption] Creating BIO buffer." << endl;
#endif // GULTRA_DEBUG

        err = (GError) bio_create_newbuffer(&bio);
        if(err != GERROR_NONE)
        {
#ifdef GULTRA_DEBUG
            cout << "[Encryption] Error creating BIO buffer : '" << gerror_to_string(err) << "'." << endl;
#endif // GULTRA_DEBUG
            return err;
        }

#ifdef GULTRA_DEBUG
        cout << "[Encryption] Reading RSA PubKey." << endl;
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
        if (BIO_read(bio->bio, (void*) out->buf, (int) out->size) < 0) {
            out->size = 0;
            return GERROR_ENCRYPT_BIOREAD;
        }

        return GERROR_NONE;
    }
    
    /*
		A note on passkey in GangTella
		
		passkey has the following pattern :
		"Byte:Byte:..."
		There is the pair key/IV. This pair is managed by OpenSSL to be
		unbreakable.
		
		It is computed using the aes-25-cbc agorithm, then concatened
		in a buffer.
		
		When you create a user using a password, it will create 
		this passkey.
		This passkey is then stored in your database.
		When you load the database, you can login to a user
		setting the correct password. This password should generate
		the same Key|IV pair.
    */
    
    /** @brief Create an encrypted pass using aes-256 algorithm.
     *  
     *  This function stores the key and the initialization vector
     *  directly in the out buffer.
     *
     *  @return
     *  - GERROR_NONE          : No errors occured.
     *  - GERROR_BADARGS       : outpass or passwd are invalid.
     *  - GERROR_BADCIPHER     : No aes-256-cbc cipher found.
     *  - GERROR_EVPBTKFAILURE : EVP_BytesToKey failed.
    **/
    gerror_t user_create_keypass(std::string& outkey, std::string& outiv, const char* passwd, size_t passwdsz)
    {
    	if(!passwd || passwdsz == 0)
			return GERROR_BADARGS;
		
		const EVP_CIPHER* cipher = EVP_get_cipherbyname("aes-256-cbc");
		if(!cipher)
		{
#ifdef GULTRA_DEBUG
			cout << "[Encryption] No such cipher !" << endl;
#endif // GULTRA_DEBUG

			return GERROR_BADCIPHER;
		}
		
		const EVP_MD* dgst = EVP_get_digestbyname("md5");
		if(!dgst)
		{
#ifdef GULTRA_DEBUG
			cout << "[Encryption] No such digest !" << endl;
#endif // GULTRA_DEBUG

			return GERROR_BADCIPHER;
		}
		
		unsigned char ukey[EVP_MAX_KEY_LENGTH];
		memset(ukey, 0, EVP_MAX_KEY_LENGTH);
		
		unsigned char uiv[EVP_MAX_IV_LENGTH];
		memset(uiv, 0, EVP_MAX_IV_LENGTH);
		
		int err = EVP_BytesToKey(cipher, dgst, NULL, (unsigned char*) passwd, (int) passwdsz, 4, ukey, uiv);
		
		if(!err)
		{
#ifdef GULTRA_DEBUG
			cout << "[Encryption] OpenSSL::EVP_BytesToKey failed !" << endl;
#endif // GULTRA_DEBUG

			return GERROR_EVPBTKFAILURE;
		}
		
		size_t ukeyl = EVP_MAX_KEY_LENGTH;
		size_t uivl  = EVP_MAX_IV_LENGTH;
		
		std::stringstream outkeystream;
		for(size_t i = 0; i < ukeyl; ++i)
		{
			outkeystream << (unsigned int) ukey[i] << ":";
		}
		outkey = outkeystream.str();
		
		std::stringstream outivstream;
		for(size_t i = 0; i < uivl; ++i)
		{
			outivstream << (unsigned int) uiv[i] << ":";
		}
		outiv = outivstream.str();
		
#ifdef GULTRA_DEBUG
		cout << "[Encryption] Key = '" << outkey << "'." << endl;
		cout << "[Encryption] Iv  = '" << outiv << "'." << endl;
#endif // GULTRA_DEBUG
		
		return GERROR_NONE;
    }
    
    bool user_check_password(std::string inkey, std::string iniv, const char* passwd, size_t passwdsz)
    {	
		std::string cmp1key, cmp1iv;
		user_create_keypass(cmp1key, cmp1iv, passwd, passwdsz);
		
		return cmp1key == inkey &&
			   cmp1iv  == iniv  &&
			   !cmp1key.empty() &&
			   !inkey.empty();
    }
    
    gerror_t AESCrypt(unsigned char* inbuf, uint32_t inbufsize, unsigned char*& outbuf, int* outlen, std::string& key, std::string& iv, bool encrypt)
    {
        unsigned int blocksize;
        EVP_CIPHER_CTX ctx;
        
        int out_len;
        int tot_len = 0;
        unsigned char* cur = inbuf;
        int tot_read = 0;
        unsigned int readbufsize = 4096;
        unsigned char* readbuf = (unsigned char*) malloc(readbufsize);
        unsigned char* end = inbuf + inbufsize - 1;
        
        EVP_CipherInit(&ctx, EVP_aes_256_cbc(), (unsigned char*) key.c_str(), (unsigned char*) iv.c_str(), encrypt ? 1 : 0);
        blocksize = EVP_CIPHER_CTX_block_size(&ctx);
        unsigned char* cipherbuf = (unsigned char*) malloc(blocksize + readbufsize);
        
        if(blocksize >= inbufsize)
        {
            EVP_CipherUpdate(&ctx, cipherbuf, &out_len, inbuf, inbufsize);
            EVP_CipherFinal(&ctx, cipherbuf, &out_len);
            outbuf = (unsigned char*) malloc(out_len);
            memcpy(outbuf, cipherbuf, out_len);
            
            if(outlen)
                *outlen = out_len;
        }
        else
        {
            while (cur != end)
            {
                int tmp = tot_len;
                
                if(end - cur + 1 >= readbufsize)
                {
                    memcpy(readbuf, cur, readbufsize);
                    EVP_CipherUpdate(&ctx, cipherbuf, &out_len, readbuf, readbufsize);
                    
                    cur = cur + readbufsize;
                    tot_read += readbufsize;
                    tot_len += out_len;
                }
                else
                {
                    // last block, so break after
                    memcpy(readbuf, cur, end - cur + 1);
                    EVP_CipherUpdate(&ctx, cipherbuf, &out_len, readbuf, (int) (end - cur + 1));
                    
                    cur = end;
                    tot_read += end - cur + 1;
                    tot_len += out_len;
                }
                
                // Write the output in the out buffer.
                outbuf = (unsigned char*) realloc(outbuf, tot_len);
                
                if(tmp)
                    memcpy(outbuf + tmp, cipherbuf, out_len);
                else
                    memcpy(outbuf, cipherbuf, out_len);
            }
            
            EVP_CipherFinal(&ctx, cipherbuf, &out_len);
            outbuf = (unsigned char*) realloc(outbuf, tot_len + out_len);
            memcpy(outbuf + tot_len, cipherbuf, out_len);
            
            if(outlen)
                *outlen = tot_len + out_len;
        }
        
        return GERROR_NONE;
    }
    
    gerror_t aes256_file(bool should_encrypt, FILE* ifp, FILE* ofp, unsigned char* ckey, unsigned char* ivec)
    {
        const unsigned BUFSIZE = 4096;
        unsigned char *read_buf = (unsigned char*) malloc(BUFSIZE);
        unsigned char *cipher_buf;
        unsigned blocksize;
        int out_len;
        EVP_CIPHER_CTX ctx;
        
        EVP_CipherInit(&ctx, EVP_aes_256_cbc(), ckey, ivec, should_encrypt);
        blocksize = EVP_CIPHER_CTX_block_size(&ctx);
        cipher_buf = (unsigned char*) malloc(BUFSIZE + blocksize);
        
        while (1) {
            
            // Read in data in blocks until EOF. Update the ciphering with each read.
            
            int numRead = (int) fread(read_buf, sizeof(unsigned char), BUFSIZE, ifp);
            EVP_CipherUpdate(&ctx, cipher_buf, &out_len, read_buf, numRead);
            fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);
            
#ifdef GULTRA_DEBUG
            cout << "[aes256_file] Read " << out_len << " bytes." << endl;
#endif
            
            if (numRead < BUFSIZE) { // EOF
                break;
            }
        }
        
        // Now cipher the final block and write it out.
        
        EVP_CipherFinal(&ctx, cipher_buf, &out_len);
        fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);
        
        // Free memory
        
        free(cipher_buf);
        free(read_buf);
        
        return GERROR_NONE;
    }
}

gerror_t encryption_init()
{
    return Encryption::Init();
}

GEND_DECL
