/*
    File        : prerequesites.h
    Description : Defines common things for several platform.
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

#ifndef __PREREQUESITES__H
#define __PREREQUESITES__H

/** @mainpage GangTella
 *
 *  ### The Goal
 *
 *  GangTella has for main purpose to make you easy to create a secret 
 *  network.
 *  
 *  ### Definitions
 *
 *  Network : Group of users. A network is defined by a database. The master's
 *  database contains every users in the network. 
 *
 *  Database : A store which contains users, their clients and their accepted
 *  users. 
 *
 *  User : A user is a human. A human is identified in the network using its
 *  nickname (username), and its key/iv pair (defined by his password).
 *
 *  Client : A client is a server which is connected to the user's server.
 *  Each client is identified by its IP and the port it has to go through.
 *
 *  Server : Structure which can handle connections to other servers.
 *
 *  ### A quick explanation
 *
 *  There are multiple layers in the GangTella network system.
 *
 *  - The Server layer : the physical low-level layer which connects two machines.
 *  It sends crypted informations using a temporary symetric key used by both
 *  machines. 
 * 
 *  - The Crypted layer : A "simple" layer which is a double-crypted 
 *  information (once by the machine, and a second time by the user).
 *
 *  - The User layer : This is the human part. The user layer is used
 *  to performs commands.
 *
**/

/* ******************************************************************* */

#define GVERSION_MAJ   "0" ///< @brief The Major version.
#define GVERSION_MIN   "1" ///< @brief The Minor version.

#define GDB_VERSION    "0A"

#define _DEBUG
#define _PANIC_ON_ERROR

#ifdef _DEBUG
#define GVERSION_BUILD "16d"
#else
#define GVERSION_BUILD "16"
#endif // _DEBUG

#define GANGTELLA_VERSION GVERSION_MAJ "." GVERSION_MIN "." GVERSION_BUILD

/*
    These are standards headers. They are common for every operating
    systems so we don't need to change any of them.
*/

#include <unistd.h>
#include <typeinfo>
#include <fstream>
#include <iostream>
#include <errno.h>
#include <string>
#include <cstring>
#include <cstdio>
#include <vector>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <map>
#include <sstream>
#include <limits>

#include <openssl/rsa.h>
#include <openssl/evp.h>

/* ******************************************************************* */



#ifdef _WIN32
/* ******************************************************************* */
/*                           Windows Header                            */
/* ******************************************************************* */

#include <windows.h>
#include <winsock2.h>

typedef char data_t; // This type is used to send or recv data.
typedef struct timespec timespec_t;

/* ******************************************************************* */





#elif defined (_LINUX)
/* ******************************************************************* */
/*                            Linux Header                             */
/* ******************************************************************* */

#include <sys/types.h>
#include <sys/socket.h>

#include <termios.h>

#ifdef _OSX
#   include <sys/time.h>
#   define CLOCK_PROCESS_CPUTIME_ID CLOCKS_PER_SEC
#   define clock_gettime clock
#   pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
//#include <unistd.h> /* close */
#include <netdb.h> /* gethostbyname */
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket(s) close(s)
typedef int SOCKET;
typedef struct sockaddr_in SOCKADDR_IN;
typedef struct sockaddr    SOCKADDR;
typedef struct in_addr     IN_ADDR;
typedef unsigned char      data_t;     // This type is used to send or recv data.
typedef struct timespec    timespec_t;

/* ******************************************************************* */

#elif defined (_OSX)

#include <sys/types.h>
#include <sys/socket.h>

#include <termios.h>

#include <sys/time.h>
#define CLOCK_PROCESS_CPUTIME_ID CLOCKS_PER_SEC
#define clock_gettime clock
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include <netinet/in.h>
#include <arpa/inet.h>
//#include <unistd.h> /* close */
#include <netdb.h> /* gethostbyname */
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket(s) close(s)
typedef int SOCKET;
typedef struct sockaddr_in SOCKADDR_IN;
typedef struct sockaddr    SOCKADDR;
typedef struct in_addr     IN_ADDR;
typedef unsigned char      data_t;     // This type is used to send or recv data.
typedef long               timespec_t;

#else

#error No socket implementation available on your platform.

#endif

// Compile time assertion
#ifdef __GNUC__
#define STATIC_ASSERT(expr, msg) \
    typedef char constraint_violated_##msg[2*((expr)!=0)-1];
#else
    #define STATIC_ASSERT(expr, msg)   \
    extern char STATIC_ASSERTION__##msg[1]; \
    extern char STATIC_ASSERTION__##msg[(expr)?1:2]
#endif /* #ifdef __GNUC__ */

STATIC_ASSERT(sizeof(char)     == 1, invalid_char_size);
STATIC_ASSERT(sizeof(short)    == 2, invalid_short_size);
STATIC_ASSERT(sizeof(int)      == 4, invalid_int_size);
STATIC_ASSERT(sizeof(float)    == 4, invalid_float_size);
STATIC_ASSERT(sizeof(long)     == 8, invalid_long_size);
STATIC_ASSERT(sizeof(double)   == 8, invalid_double_size);

// These defines are for auto-completion of argues.
#define SERVER_MAXCLIENTS    10
#define SERVER_MAXBUFSIZE    1024
#define SERVER_MAXKEYSIZE    EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH + 100
#define RSA_SIZE             256  // Size of chunk in RSA. Data must be 256 - 11 size.
#define ID_CLIENT_INVALID    0

#ifdef _DEBUG
#   define GULTRA_DEBUG         1    // Define this if you want every debug things.
#endif // _DEBUG

// C++ special declaration
#ifdef __cplusplus
#   define GBEGIN_DECL namespace Gangtella {
#   define GEND_DECL   }
#else
#   define GBEGIN_DECL
#   define GEND_DECL
#endif

GBEGIN_DECL

typedef char          byte_t;
typedef unsigned char ubyte_t;
typedef unsigned char uchar_t;
typedef uint64_t      netid__;
typedef std::vector<std::string> stringlist_t;

// As we want the same size_t type for every platform, we make it
// always uint64_t. 
#define size_t uint64_t

// The netid_t is a type corresponding to the id
// of a network. This id is computed from the creator
// of the network, using is public key. This number
// is guarenteed to be unique. You must know it to enter
// the network.
typedef union {
    netid__  l;    // The long type.
    ubyte_t  b[4]; // The bytes side.
} netid_t;

// stat_t corresponds to a status type. This status must be
// a value from 0.00 to 1.00.
// 0.00 corresponds to a new user, 1.00 to a master.
// A master know every one in the network.
// This value is computed using the algorithm num_of_master_accepted/num_of_master.
typedef float stat_t;

typedef enum GError
{
    GERROR_NONE              = 0,
    GERROR_BADARGS           = 1,  // Argues given are either invalid either null.
    GERROR_CANTOPENFILE      = 2,
    GERROR_BUFSIZEEXCEEDED   = 3,
    GERROR_IO_CANTREAD       = 4,
    GERROR_INVALID_SOCKET    = 5,
    GERROR_INVALID_HOST      = 6,
    GERROR_INVALID_CONNECT   = 7,
    GERROR_CANT_SEND_PACKET  = 8,
    GERROR_CANT_CLOSE_SOCKET = 9,
    GERROR_WSASTARTUP        = 10, // Returned when WSA has a problem (only windows)
    GERROR_INVALID_BINDING   = 11,
    GERROR_INVALID_LISTENING = 12,
    GERROR_THREAD_CREATION   = 13,
    GERROR_MUTEX_LOCK        = 14,
    GERROR_MUTEX_UNLOCK      = 15,
    GERROR_WSACLEANING       = 16,
    GERROR_ENCRYPT_GENERATE  = 17,
    GERROR_ENCRYPT_BIO       = 18,
    GERROR_ENCRYPT_BIOREAD   = 19,
    GERROR_ENCRYPT_WRITE     = 20,
    GERROR_INVALID_PACKET    = 21,
    GERROR_USR_NODB          = 22,
    GERROR_USR_NOKEY         = 23,
    GERROR_USR_BADPSWD       = 24,
    GERROR_BADCIPHER         = 25,
    GERROR_EVPBTKFAILURE     = 26,
    GERROR_TIMEDOUT          = 27,
    GERROR_NET_NOTFOUND      = 28,
    GERROR_NET_INVALID       = 29,
    GERROR_NET_ALRINIT       = 30,
    GERROR_NOTIMPLEMENTED    = 31,
    GERROR_BADUSR            = 32,
    GERROR_WSAVERSION        = 33,
    GERROR_ALLOC             = 34,
    GERROR_ANSWER_BAD        = 35,
    GERROR_ANSWER_INVALID    = 36,
    GERROR_DB_BADVERSION     = 37,
    GERROR_DB_BADAUTOSAVE    = 38,
    GERROR_ENCRYPT_NOSSL     = 39,
    GERROR_ENCRYPT_PUBKEY    = 40,
    GERROR_USR_NODBPASS      = 41,
    GERROR_DB_BADHEADER      = 42,
    GERROR_DB_BADDECRYPT     = 43,
    GERROR_DB_FATALSTRUCT    = 44,
    GERROR_NOUSER            = 45,
    GERROR_NOUSERPASS        = 46,
    GERROR_NORECEIVE         = 47,
    GERROR_GCRYPT_BADPOS     = 48,
    GERROR_DB_NOUSER         = 49,

    GERROR_MAX               = 50  // Number of errors
} GError;
typedef int gerror_t;

// Return the error description for given error number
const char* gerror_to_string(GError err);
const char* gerror_to_string(gerror_t err);

// Timer for performance
// Taken from http://stackoverflow.com/questions/6749621/high-resolution-timer-in-linux

// call this function to start a nanosecond-resolution timer
timespec_t timer_start();

// call this function to end a timer, returning nanoseconds elapsed as a long
long timer_end(timespec_t start_time);

/* Example

struct timespec vartime = timer_start();  // begin a timer called 'vartime'
double variance = var(input, MAXLEN);  // perform the task we want to time
long time_elapsed_nanos = timer_end(vartime);
printf("Variance = %f, Time taken (nanoseconds): %ld\n", variance, time_elapsed_nanos);

*/

bool gthread_mutex_lock(pthread_mutex_t* mutex);
bool gthread_mutex_unlock(pthread_mutex_t* mutex);

// A standard buffer
typedef struct {
    unsigned char   buf[SERVER_MAXBUFSIZE];
    size_t size;
} buffer_t;

// A static buffer.
// Lenght can't be superior to UINT16_MAX, this buffer
// should always be used for network.
// Buffer is always lenght+1 of size, because it always terminate with '\0'
// by convention, to allow automatic string conversion.
typedef struct netbuffer_t {
    char*    buf;   // Contains the data.
    uint16_t lenght;// Contains the lenght of the data.
    
    netbuffer_t() {
        buf = nullptr;
        lenght = 0;
    }
} netbuffer_t;

gerror_t buffer_copy(buffer_t& dest, const buffer_t& src);

// Threaded log

using std::cout;
using std::endl;
extern pthread_mutex_t __console_mutex;

#define cout  gthread_mutex_lock(&__console_mutex); cout
#define endl  endl; gthread_mutex_unlock(&__console_mutex)
#define ecout ""; gthread_mutex_unlock(&__console_mutex)

GEND_DECL

#include "serializer.h"

GBEGIN_DECL

// From http://oopweb.com/CPP/Documents/CPPHOWTO/Volume/C++Programming-HOWTO-7.html
void Tokenize(const std::string& str, std::vector<std::string>& tokens, const std::string& delimiters = " ");

// This part is to serialize and deserialize easily data from text and to text.
// Data send using this method must be crypted to guarantee security because they are
// human readable !!

template <typename T>
std::string to_text(const T& object) {
    cout << "[Textizer] No implementation found for type '" << typeid(object).name() << "'." << endl;
    return "";
}

template <typename T>
T from_text(const std::string& object) {
    cout << "[Textizer] No implementation found for type '" << typeid(object).name() << "'." << endl;
    return T();
}

// Initialize network depending on platform. (Start WSA2.0)
gerror_t NetworkInit();

// A private customized recv() function.
ssize_t grecv(int socket, void* buffer, size_t lenght, int flags);

// A platform independent function to get a password from command prompt, but without showing it.
// Modified from http://www.cplusplus.com/articles/E6vU7k9E/
std::string getpass(bool show_asterisk = true);

// Copy a string buffer with its lenght (uint16 version)
void strbufcreateandcopy(char*& outstr, uint16_t& outlen, const char* in, uint16_t inlen);

// Create an empty netbuffer
netbuffer_t* netbuf_new(uint16_t lenght);
netbuffer_t* netbuf_new(const char* data, uint16_t lenght);
// Copy and create new buffer.
netbuffer_t* netbuf_copy(const netbuffer_t& other);
// Copy from raw data.
void netbuf_copyraw(netbuffer_t* to, const char* from, uint16_t lenght);
// Free the buffer and reset it.
void netbuf_delete(netbuffer_t* buf);
void netbuf_free(netbuffer_t*& buf);// Also nullize the buffer.

#include "structs.h"

class Server;

struct session_t
{
    database_t* database;
    user_t*     user;
    Server*   server;
    bool _treatingcommand;
};

extern session_t globalsession;

// Macro _PANIC_ON_ERROR can be set by the user before compiling the Engine to make
// an Engine really not tolerating any error.
#ifndef _PANIC_ON_ERROR
#define exit(a) return a
#else
#define exit(a) cout << "[Panic] Error : (" << __FUNCTION__ << ":" << __LINE__ << ") " << gerror_to_string(a) << endl; _exit(a)
#endif

// gnotifiate subsystem - 28/06/2015

/** @brief Notifiate printf-like style some informations depending on the log 
 *  level. You also can set different streams using gnotifiate_setloglevelfile().
**/
void gnotifiate(int level, const char* format, ...);

#define gnotifiate_error(fmt, ...) gnotifiate (1, fmt, ##__VA_ARGS__ )
#define gnotifiate_warn(fmt, ...) gnotifiate (2, fmt, ##__VA_ARGS__ )
#define gnotifiate_info(fmt, ...) gnotifiate (3, fmt, ##__VA_ARGS__ )

/** @brief Set the default logging files for given level.
**/
void gnotifiate_setloglevelfile(int level, FILE* file);

GEND_DECL

#endif // __PREREQUESITES__H
