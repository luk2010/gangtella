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

typedef struct database_blockinfo_t {
    
    uint16_t type; // Type of the block. For the alignment, we use uint16_t.
    uint16_t size; // Size of the block, in bytes.
    
    database_blockinfo_t() {
        type = 0;
        size = 0;
    }
    
} database_blockinfo_t; // blockinfo is 32 bits.

typedef struct database_block_t {
    
    database_blockinfo_t info;
    // Size of the data is info.size - sizeof(database_blockinfo_t) .
    
    database_block_t() : info() {
        
    }
    
} database_block_t;

typedef struct database_header_t {
    
    database_block_t block;
    uint16_t version_build;
    uint32_t magic;
    
    database_header_t() : block(), version_build(0), magic(0) {
        
    }
    
} database_header_t;

typedef struct database_blk_headerext_t {
    database_block_t block;
    netbuffer_t name;
    
    database_blk_headerext_t() : block(), name() {
        
    }
    
    ~database_blk_headerext_t() {
        netbuf_delete(&name);
    }
    
} database_blk_headerext_t;

typedef struct database_blk_user_t {
    database_block_t block;
    netbuffer_t name;
    netbuffer_t key;
    netbuffer_t iv;
    float    status;
    
    database_blk_user_t() : block(), name(), key(), iv(), status(0.0f) {
        
    }
    
    ~database_blk_user_t() {
        netbuf_delete(&name);
        netbuf_delete(&key);
        netbuf_delete(&iv);
    }
    
} database_blk_user_t;

typedef struct database_blk_client_t {
    database_block_t block;
    netbuffer_t ip;
    uint16_t port;
    
    database_blk_client_t() : block(), ip(), port(0) {
        
    }
    
    ~database_blk_client_t() {
        netbuf_delete(&ip);
    }
    
} database_blk_client_t;

#pragma pack()

database_user_t* __current_user = nullptr;

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

void database_readformattedstring(const char*& cursor, char** outstr, uint16_t* outlen)
{
    // A formated string is a uint16_t, followed by a sequence of bytes.
    uint16_t retlen = 0;
    char* retstr = (char*) malloc(SERVER_MAXBUFSIZE);
    database_readuint16(cursor, &retlen);
    if(retlen > 0) {
        database_readstring(cursor, &retstr, (uint32_t) retlen);
    }
    
    if(outstr) {
        *outstr = (char*) malloc(retlen);
        memcpy(*outstr, retstr, retlen);
    }
    if(outlen) {
        *outlen = retlen;
    }
}

void database_readfloat(const char*& cursor, float* out)
{
    // To read float, we read a uint32 then convert it to float.
    FloatUint conv;
    database_readuint32(cursor, &conv.bits);
    *out = conv.value;
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
    to->m_name = netbuf_new(dbname.c_str(), dbname.length());
    
    Encryption::user_create_keypass(to->key, to->iv, dbpass.c_str(), dbpass.length());
    
    return GERROR_NONE;
}

gerror_t database_create2(database_t*& to, const std::string& key, const std::string& iv)
{
    to = new database_t;
    to->m_name = netbuf_new(0);
    to->key = key;
    to->iv = iv;
    
    return GERROR_NONE;
}

void database_readblockinfo(const char*& cursor, database_blockinfo_t* blkinfo)
{
    database_readuint16(cursor, &blkinfo->type);
    database_readuint16(cursor, &blkinfo->size);
}

void database_internal_adduserblk(database_t* db, database_blk_user_t& user)
{
    database_user_t* nuser = (database_user_t*) malloc(sizeof(database_user_t));
    nuser->status = user.status;
    
    nuser->m_name = netbuf_copy(user.name);
    nuser->m_key  = netbuf_copy(user.key);
    nuser->m_iv   = netbuf_copy(user.iv);
    
    db->data.push_back(nuser);
    __current_user = nuser;
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
        
        database_readuint16(cursor, &to->m_name->lenght);
        database_readstring(cursor, &to->m_name->buf, to->m_name->lenght);
        
#ifdef GULTRA_DEBUG
        cout << "   lname = " << (uint32_t) to->m_name->lenght << endl;
        cout << "   name  = " << (const char*) to->m_name->buf << endl;
#endif
    }
    
    else if(blkinfo.type == BT_USER)
    {
        // Here we enter a new section, the user section.
        
        database_blk_user_t new_user;
        database_readformattedstring(cursor, & new_user.name.buf, & new_user.name.lenght);
        database_readformattedstring(cursor, & new_user.key.buf,  & new_user.key.lenght);
        database_readformattedstring(cursor, & new_user.iv.buf,   & new_user.iv.lenght);
        database_readfloat(cursor, & new_user.status);
        
#ifdef GULTRA_DEBUG
        cout << "[database_load] User found : " << endl;
        cout << "   name = " << (const char*) new_user.name.buf << endl;
        cout << "   key  = " << (const char*) new_user.key.buf  << endl;
        cout << "   iv   = " << (const char*) new_user.iv.buf   << endl;
        cout << "   status = " << new_user.status << endl;
#endif
        
        database_internal_adduserblk(to, new_user);
    }
    
    else if(blkinfo.type == BT_CLIENT)
    {
        if(!__current_user) {
            exit(GERROR_DB_NOUSER);
        }
        // Here we read the hardware clients that have connected to this server
        // during the session with current user.
        database_blk_client_t hclient;
        database_readformattedstring(cursor, &hclient.ip.buf, & hclient.ip.lenght);
        database_readuint16(cursor, & hclient.port);
        
#ifdef GULTRA_DEBUG
        cout << "[database_load] Hardware Client found : " << endl;
        cout << "   ip = " << (const char*) hclient.ip.buf << endl;
        cout << "   port = " << (uint32_t) hclient.port << endl;
#endif
        
        database_clientinfo_t nclient;
        nclient.ip = std::string(hclient.ip.buf, hclient.ip.lenght);
        nclient.port = hclient.port;
        __current_user->clients.push_back(nclient);
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
    free(buffer);
    
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
        if(username == std::string(db->data[i]->m_name->buf))
            return db->data[i];
    }
    
    return nullptr;
}

database_user_t* database_create_user(database_t* db, const std::string& username, const std::string& userpass)
{
    database_user_t* nuser = (database_user_t*) malloc(sizeof(database_user_t));
    nuser->m_name = netbuf_new(username.c_str(), username.length());
    
    std::string key; std::string iv;
    Encryption::user_create_keypass(key, iv, userpass.c_str(), userpass.size());
    
    nuser->m_key = netbuf_new(key.c_str(), key.length());
    nuser->m_iv  = netbuf_new(iv.c_str(),  iv.length());
    
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
    database_writeuint16(f, headerext.name.lenght);
    database_writestring(f, headerext.name.buf, headerext.name.lenght);
}

void database_writefloat(std::string& f, float& rhs)
{
    FloatUint conv;
    conv.value = rhs;
    database_writeuint32(f, conv.bits);
}

void database_writeuserblk(std::string& f, database_blk_user_t& userblk)
{
    database_writeuint16(f, userblk.block.info.type);
    database_writeuint16(f, userblk.block.info.size);
    
    database_writeuint16(f, userblk.name.lenght);
    database_writestring(f, userblk.name.buf, userblk.name.lenght);
    database_writeuint16(f, userblk.key.lenght);
    database_writestring(f, userblk.key.buf, userblk.key.lenght);
    database_writeuint16(f, userblk.iv.lenght);
    database_writestring(f, userblk.iv.buf, userblk.iv.lenght);
    database_writefloat(f, userblk.status);
}

void database_writeclientblk(std::string& f, database_blk_client_t& clientblk)
{
    database_writeuint16(f, clientblk.block.info.type);
    database_writeuint16(f, clientblk.block.info.size);
    
    database_writeuint16(f, clientblk.ip.lenght);
    database_writestring(f, clientblk.ip.buf, clientblk.ip.lenght);
    database_writeuint16(f, clientblk.port);
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
    netbuf_copyraw(&blkheaderext.name, database->m_name->buf, database->m_name->lenght);
    
#ifdef GULTRA_DEBUG
    cout << "[database_save] Writing HeaderExt block : " << endl;
    cout << "   name_lenght = " << blkheaderext.name.lenght << endl;
    cout << "   name = " << (const char*) blkheaderext.name.buf << endl;
#endif
    database_writeheaderext(in, blkheaderext);
    
    // Destroy headerext malloc
    netbuf_delete(&blkheaderext.name);
    
    // For every users in the database
    for(uint32_t i = 0; i < database->data.size(); ++i)
    {
        database_user_t* dbuser = database->data.at(i);
        
        database_blk_user_t dbuserblk;
        dbuserblk.block.info.type = BT_USER;
        
        netbuf_copyraw(& dbuserblk.name, dbuser->m_name->buf, dbuser->m_name->lenght);
        netbuf_copyraw(& dbuserblk.key,  dbuser->m_key->buf,  dbuser->m_key->lenght);
        netbuf_copyraw(& dbuserblk.iv,   dbuser->m_iv->buf,   dbuser->m_iv->lenght);
        
        dbuserblk.status = dbuser->status;
        
        dbuserblk.block.info.size = sizeof(database_blk_user_t) + dbuserblk.name.lenght + dbuserblk.key.lenght + dbuserblk.iv.lenght;
        database_writeuserblk(in, dbuserblk);
        
        // Write every hardware clients
        for(unsigned int j = 0; j < database->data[i]->clients.size(); ++j)
        {
            database_clientinfo_t& cinfo = database->data[i]->clients.at(j);
            
            database_blk_client_t dbclientblk;
            dbclientblk.block.info.type = BT_CLIENT;
            
            netbuf_copyraw(&dbclientblk.ip, cinfo.ip.c_str(), cinfo.ip.length());
            dbclientblk.port = cinfo.port;
            
            dbclientblk.block.info.size = sizeof(database_blk_client_t) + dbclientblk.ip.lenght;
            database_writeclientblk(in, dbclientblk);
        }
    }
    
#ifdef GULTRA_DEBUG
    cout << "[database_save] with key = " << database->key << endl;
#endif
    
    // Crypt the buffer with password
    gcrypt(in, out, database->key);
    //out = in;
    
    // Write everything in the file
    FILE* fdb = fopen(database->m_name->buf, "wb");
    fwrite(out.c_str(), out.length(), 1, fdb);
    fclose(fdb);
    
    return GERROR_NONE;
}

GEND_DECL