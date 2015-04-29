/*
 File        : database.cpp
 Description : Handles every database related functions.
 */

/*
 GangTella Project
 Copyright (C) 2014 - 2015  Luk2010
 
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

#include "database.h"
#include "encryption.h"
#include "serializer.h"
#include "gcrypt.h"

GBEGIN_DECL

const uint16_t DBVERSION = 0x0001;
const uint32_t DBMAGIC   = 0x0BADB002;

union FloatUint
{
    uint32_t bits;
    float    value;
};

enum BlockType
{
    BT_HEADER       = 0x0000,
    BT_USER         = 0x0001,
    BT_HEADEREXT    = 0x0002,
    BT_CLIENT       = 0x0003,
    BT_ACCEPTED     = 0x0004
};

#pragma pack(1)

typedef struct {
    
    uint16_t type; // Type of the block. For the alignment, we use uint16_t.
    uint16_t size; // Size of the block, in bytes.
    
} database_blockinfo_t; // blockinfo is 32 bits.

typedef struct {
    
    database_blockinfo_t info;
    // Size of the data is info.size - sizeof(database_blockinfo_t) .
    
} database_block_t;

typedef struct {
    
    database_block_t block;
    uint16_t version_build;
    uint32_t magic;
    
} database_header_t;

typedef struct {
    database_block_t block;
    uint16_t name_lenght;
    char*    name;
} database_blk_headerext_t;

#pragma pack()

/* Read to the buffer (size 256) from encoded file. DO NOT perform any decryption. */
uint32_t database_intern_readtobuf(FILE* encfile, unsigned char* buf256)
{
    return (uint32_t) fread(buf256, sizeof(unsigned char), 256, encfile);
}

void database_readuint8(const char*& infp, uint8_t* out)
{
    memcpy(out, infp, sizeof(uint8_t));
    *out = deserialize<uint8_t>(*out);
    infp++;
}

void database_readuint16(const char*& infp, uint16_t* out)
{
    memcpy(out, infp, sizeof(uint16_t));
    *out = deserialize<uint16_t>(*out);
    infp += sizeof(uint16_t);
}

void database_readuint32(const char*& infp, uint32_t* out)
{
    memcpy(out, infp, sizeof(uint32_t));
    *out = deserialize<uint32_t>(*out);
    infp += sizeof(uint32_t);
}

void database_readstring(const char*& cursor, char** out, uint32_t lenght)
{
    *out = (char*) malloc(lenght+1);
    memcpy(*out, cursor, lenght);
    (*out)[lenght] = '\0';
    cursor += lenght;
}

void database_readformattedstring(std::string* out, unsigned char* cursor)
{
    /*
    uint16_t lenght;
    database_readuint16(&lenght, cursor);
    char* buf = (char*) malloc(lenght+1);
    database_readstring(&buf, lenght, cursor);
    *out = std::string(buf);
     */
}

void database_readfloat(float* out, unsigned char* cursor)
{
    /*
    FloatUint ret;
    database_readuint32(&ret.bits, cursor);
    *out = ret.value;
     */
}

gerror_t database_readheader(const char*& infp, database_header_t* header)
{
    database_readuint16(infp, &header->version_build);
    database_readuint32(infp, &header->magic);
    
    return GERROR_NONE;
}

gerror_t database_create(database_t*& to, const std::string& dbname, const std::string& dbpass)
{
    to = (database_t*) malloc(sizeof(database_t));
    to->lname = dbname.length();
    to->name = (char*) malloc(to->lname+1);
    memcpy(to->name, dbname.c_str(), dbname.length());
    to->name[to->lname] = '\0';
    
    Encryption::user_create_keypass(to->key, to->iv, dbpass.c_str(), dbpass.length());
    
    return GERROR_NONE;
}

gerror_t database_create2(database_t*& to, const std::string& key, const std::string& iv)
{
    to = (database_t*) malloc(sizeof(database_t));
    to->lname = 0;
    to->name = nullptr;
    to->key = key;
    to->iv = iv;
    
    return GERROR_NONE;
}

void database_readblockinfo(const char*& cursor, database_blockinfo_t* blkinfo)
{
    database_readuint16(cursor, &blkinfo->type);
    database_readuint16(cursor, &blkinfo->size);
}

gerror_t database_process_block(const char*& cursor, database_t*& to, const std::string& dbname, const std::string& key, const std::string& iv)
{
    database_blockinfo_t blkinfo;
    database_readblockinfo(cursor, &blkinfo);
    
    if(blkinfo.type == BT_HEADER)
    {
        database_header_t header;
        database_readheader(cursor, &header);
        header.block.info = blkinfo;
        
#ifdef GULTRA_DEBUG
        cout << "[database_load] header struct {" << endl;
        cout << "   block.info.type = " << header.block.info.type << endl;
        cout << "   block.info.size = " << header.block.info.size << endl;
        cout << "   version_build   = " << header.version_build << endl;
        cout << "   magic           = " << header.magic << endl;
        cout << "};" << endl;
#endif
        
        if (header.magic != DBMAGIC) {
            cout << "[database_load] Bad Magic Number (" << (uint32_t) header.magic << "!=" << (uint32_t) DBMAGIC << ")." << endl;
            exit(GERROR_DB_BADHEADER);
        }
        
        if (header.version_build != DBVERSION) {
            exit(GERROR_DB_BADHEADER);
        }
        
        database_create2(to, key, iv);
    }
    
    else if(blkinfo.type == BT_HEADEREXT)
    {
        // Here we copy some informations about the database.
        
#ifdef GULTRA_DEBUG
        cout << "[database_load] Header Extension found : " << endl;
#endif
        
        database_readuint16(cursor, &to->lname);
        database_readstring(cursor, &to->name, to->lname);
        
#ifdef GULTRA_DEBUG
        cout << "   lname = " << (uint32_t) to->lname << endl;
        cout << "   name  = " << (const char*) to->name << endl;
#endif
    }
    
    return GERROR_NONE;
}

gerror_t database_load(database_t*& to, const std::string& dbname, const std::string& dbpass, bool autocreateIfInexistante)
{
    // Read the whole file into a string
    FILE* dbfile = fopen(dbname.c_str(), "rb");
    if(!dbfile) {
        if(autocreateIfInexistante)
            return database_create(to, dbname, dbpass);
        
        exit(GERROR_CANTOPENFILE);
    }
    
    // Initialize the database
    //to = (database_t*) malloc(sizeof(database_t));
    
    fseek(dbfile, 0, SEEK_END);
    size_t sz = (size_t) ftell(dbfile);
    rewind(dbfile);
    
#ifdef GULTRA_DEBUG
    cout << "File size = " << sz << endl;
#endif
    
    char* buffer = (char*) malloc(sz);
    fread(buffer, 1, sz, dbfile);
    
#ifdef GULTRA_DEBUG
    cout << "Buffer = " << buffer << endl;
#endif
    
    // Close the file and process the buffer
    fclose(dbfile);
    
    std::string in(buffer, sz);
    std::string out;
    
#ifdef GULTRA_DEBUG
    cout << "[database_load] in = " << (uint32_t) in.c_str()[3] << endl;
#endif
    
    // Uncrypt buffer, creating the key
    std::string ikey;
    std::string iiv;
    Encryption::user_create_keypass(ikey, iiv, dbpass.c_str(), dbpass.length());
    guncrypt(in, out, ikey);
    
    const char* cursor = out.c_str();
    const char* begin = cursor;
    
#ifdef GULTRA_DEBUG
    cout << "[database_load] decrypted = { "; gthread_mutex_unlock(&__console_mutex);
    for(unsigned int i = 0; i < out.length(); ++i) {
        cout << (uint32_t) cursor[i] << ":"; gthread_mutex_unlock(&__console_mutex);
    }
    cout << " }" << endl;
#endif
    
    // Now, read everything.
    
    while (cursor - begin < out.length())
    {
        // Process every block
        database_process_block(cursor, to, dbname, ikey, iiv);
    }
    /*
    while(cursor != end)
    {
        memcpy(&block, cursor, sizeof(database_block_t));
        cursor += sizeof(database_block_t);
        
        if(end - cursor + 1 < block.info.size - sizeof(database_blockinfo_t))
        {
            exit(GERROR_DB_FATALSTRUCT);
        }
        
        if(block.info.type == BT_USER)
        {
            // We have a new user
            database_user_t* usr = (database_user_t*) malloc(sizeof(database_user_t));
            
            database_readuint16(&usr->lname, cursor);
            database_readstring(&usr->name, usr->lname, cursor);
            
            database_readuint16(&usr->lkey, cursor);
            database_readstring(&usr->key, usr->lkey, cursor);
            
            database_readuint16(&usr->liv, cursor);
            database_readstring(&usr->iv, usr->liv, cursor);
            
            database_readfloat(&usr->status, cursor);
            
            to->data.push_back(usr);
            curuser = usr;
        }
        
        else if(block.info.type == BT_HEADEREXT)
        {
            // Here we copy some informations about the database.
            
            to->key = inkey;
            to->iv  = iniv;
            to->path = dbname;
            
            database_readuint16(&to->lname, cursor);
            database_readstring(&to->name, to->lname, cursor);
        }
        
        else if(block.info.type == BT_CLIENT)
        {
            if(curuser)
            {
                database_clientinfo_t cinfo;
                database_readformattedstring(&cinfo.ip, cursor);
                database_readformattedstring(&cinfo.port, cursor);
                curuser->clients.push_back(cinfo);
            }
        }
        
        else if(block.info.type == BT_ACCEPTED)
        {
            if(curuser)
            {
                // Normally, this block tell that a given user is already accepted.
                // We stores its name, its key/iv pair.
                database_accepted_user_t auser;
                database_readformattedstring(&auser.name, cursor);
                database_readformattedstring(&auser.keys.key, cursor);
                database_readformattedstring(&auser.keys.iv, cursor);
                curuser->acceptedusers.push_back(auser);
            }
        }
    }
     
    */
    
    return GERROR_NONE;
}

database_user_t* database_find_user(database_t* db, const std::string& username)
{
    for(unsigned int i = 0; i < db->data.size(); ++i)
    {
        if(username == std::string(db->data[i]->name))
            return db->data[i];
    }
    
    return nullptr;
}

database_user_t* database_create_user(database_t* db, const std::string& username, const std::string& userpass)
{
    database_user_t* nuser = (database_user_t*) malloc(sizeof(database_user_t));
    nuser->lname = username.size();
    nuser->name = (char*) malloc(nuser->lname)+1;
    strcpy(nuser->name, username.c_str());
    nuser->name[nuser->lname] = 0;
    
    std::string key; std::string iv;
    Encryption::user_create_keypass(key, iv, userpass.c_str(), userpass.size());
    
    nuser->lkey = key.size();
    nuser->key = (char*) malloc(nuser->lkey)+1;
    strcpy(nuser->key, key.c_str());
    nuser->key[nuser->lkey] = 0;

    nuser->liv = iv.size();
    nuser->iv = (char*) malloc(nuser->liv)+1;
    strcpy(nuser->iv, iv.c_str());
    nuser->iv[nuser->liv] = 0;
    
    nuser->status = 0.0f;
    
    db->data.push_back(nuser);
    return nuser;
}

void database_writeuint8(std::string& f, uint8_t rhs)
{
    uint8_t w = serialize<uint8_t>(rhs);
    f.push_back(w);
}

void database_writeuint16(std::string& f, uint16_t rhs)
{
    uint16_t w = serialize<uint16_t>(rhs);
    uint8_t* tmp = (uint8_t*) &w;
    f.push_back(tmp[0]);
    f.push_back(tmp[1]);
}

void database_writeuint32(std::string& f, uint32_t rhs)
{
    uint32_t w = serialize<uint32_t>(rhs);
    uint8_t* tmp = (uint8_t*) &w;
    f.push_back(tmp[0]);
    f.push_back(tmp[1]);
    f.push_back(tmp[2]);
    f.push_back(tmp[3]);
}

void database_writeheader(std::string& f, database_header_t& head)
{
    database_writeuint16(f, head.block.info.type);
    database_writeuint16(f, head.block.info.size);
    
    database_writeuint16(f, head.version_build);
    
    database_writeuint32(f, head.magic);
}

void database_writestring(std::string& f, const char* str, uint16_t len)
{
    uint32_t lennorm = (uint32_t) len;
    for(uint32_t i = 0; i < lennorm; ++i)
        database_writeuint8(f, (uint8_t) str[i]);
}

void database_writeheaderext(std::string& f, database_blk_headerext_t& headerext)
{
    database_writeuint16(f, headerext.block.info.type);
    database_writeuint16(f, headerext.block.info.size);
    database_writeuint16(f, headerext.name_lenght);
    database_writestring(f, headerext.name, headerext.name_lenght);
}

gerror_t database_save(database_t* database)
{
    // New version
    
    // Create buffer
    std::string in;
    std::string out;
    
    // Fill the in buffer
    
    // Header
    database_header_t head;
    head.magic = DBMAGIC;
    head.version_build = DBVERSION;
    head.block.info.size = sizeof(database_header_t);
    head.block.info.type = BT_HEADER;
    
    database_writeheader(in, head);
    
    // Header Extension
    database_blk_headerext_t blkheaderext;
    blkheaderext.block.info.type = BT_HEADEREXT;
    blkheaderext.block.info.size = sizeof(database_blk_headerext_t);
    blkheaderext.name_lenght = database->lname;
    blkheaderext.name = (char*) malloc(database->lname+1);
    memcpy(blkheaderext.name, database->name, database->lname);
    blkheaderext.name[blkheaderext.name_lenght] = '\0';
    
#ifdef GULTRA_DEBUG
    cout << "[database_save] Writing HeaderExt block : " << endl;
    cout << "   name_lenght = " << blkheaderext.name_lenght << endl;
    cout << "   name = " << (const char*) blkheaderext.name << endl;
#endif
    database_writeheaderext(in, blkheaderext);
    
#ifdef GULTRA_DEBUG
    cout << "[database_save] with_key = " << database->key << endl;
#endif
    
    // Crypt the buffer with password
    gcrypt(in, out, database->key);
    //out = in;
    
    // Write everything in the file
    FILE* fdb = fopen(database->name, "wb");
    fwrite(out.c_str(), out.length(), 1, fdb);
    fclose(fdb);
    
    return GERROR_NONE;
}

GEND_DECL