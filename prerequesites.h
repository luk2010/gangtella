/*
    File        : prerequesites.h
    Description : Defines common things for several platform.
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

#ifndef __PREREQUESITES__H
#define __PREREQUESITES__H

/* ******************************************************************* */

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

// Comment tis line if you do not want the encryption module.
// THIS IS VERY RECOMMENDED TO KEEP IT
#define GENCRYPT_RSA

#ifdef GENCRYPT_RSA
#   include <openssl/rsa.h>
#endif // GENCRYPT_RSA

/* ******************************************************************* */




#ifdef _WIN32
/* ******************************************************************* */
/*                           Windows Header                            */
/* ******************************************************************* */

#include <windows.h>
#include <winsock2.h>

/* ******************************************************************* */





#elif defined (_LINUX)
/* ******************************************************************* */
/*                            Linux Header                             */
/* ******************************************************************* */

#include <sys/types.h>
#include <sys/socket.h>
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

/* ******************************************************************* */



#else

#error No Implementation of socket found.

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
STATIC_ASSERT(sizeof(double)   == 8, invalid_double_size);

// These defines are for auto-completion of argues.
#define CLIENT_PORT          8377 // Where our port will connect
#define SERVER_PORT          8378 // Where other client will connect
#define SERVER_MAXCLIENTS    10
#define SERVER_MAXBUFSIZE    1024
#define RSA_SIZE             256  // Size of chunk in RSA. Data must be 256 - 11 size.

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

    GERROR_MAX               = 22  // Number of errors
} GError;
typedef int gerror_t;

// Return the error description for given error number
const char* gerror_to_string(gerror_t& err);

// Timer for performance
// Taken from http://stackoverflow.com/questions/6749621/high-resolution-timer-in-linux

// call this function to start a nanosecond-resolution timer
struct timespec timer_start();

// call this function to end a timer, returning nanoseconds elapsed as a long
long timer_end(struct timespec start_time);

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

gerror_t buffer_copy(buffer_t& dest, const buffer_t& src);

GEND_DECL

#include "serializer.h"

#endif // __PREREQUESITES__H
