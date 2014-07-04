/*
    This file is part of the GangTella project
*/

#include "prerequesites.h"

GBEGIN_DECL

#ifdef _WIN32

LARGE_INTEGER
getFILETIMEoffset()
{
    SYSTEMTIME s;
    FILETIME f;
    LARGE_INTEGER t;

    s.wYear = 1970;
    s.wMonth = 1;
    s.wDay = 1;
    s.wHour = 0;
    s.wMinute = 0;
    s.wSecond = 0;
    s.wMilliseconds = 0;
    SystemTimeToFileTime(&s, &f);
    t.QuadPart = f.dwHighDateTime;
    t.QuadPart <<= 32;
    t.QuadPart |= f.dwLowDateTime;
    return (t);
}

int
clock_gettime(int X, struct timeval *tv)
{
    LARGE_INTEGER           t;
    FILETIME            f;
    double                  microseconds;
    static LARGE_INTEGER    offset;
    static double           frequencyToMicroseconds;
    static int              initialized = 0;
    static BOOL             usePerformanceCounter = 0;

    if (!initialized) {
        LARGE_INTEGER performanceFrequency;
        initialized = 1;
        usePerformanceCounter = QueryPerformanceFrequency(&performanceFrequency);
        if (usePerformanceCounter) {
            QueryPerformanceCounter(&offset);
            frequencyToMicroseconds = (double)performanceFrequency.QuadPart / 1000000.;
        } else {
            offset = getFILETIMEoffset();
            frequencyToMicroseconds = 10.;
        }
    }
    if (usePerformanceCounter) QueryPerformanceCounter(&t);
    else {
   GetSystemTimeAsFileTime(&f);
        t.QuadPart = f.dwHighDateTime;
        t.QuadPart <<= 32;
        t.QuadPart |= f.dwLowDateTime;
    }

    t.QuadPart -= offset.QuadPart;
    microseconds = (double)t.QuadPart / frequencyToMicroseconds;
    t.QuadPart = microseconds;
    tv->tv_sec = t.QuadPart / 1000000;
    tv->tv_usec = t.QuadPart % 1000000;
    return (0);
}

#define CLOCK_PROCESS_CPUTIME_ID 0

// call this function to start a nanosecond-resolution timer
struct timespec timer_start(){
    struct timespec start_time;

    struct timeval st_v;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &st_v);

    start_time.tv_sec  = st_v.tv_sec;
    start_time.tv_nsec = st_v.tv_usec * 1000;
    return start_time;
}

// call this function to end a timer, returning nanoseconds elapsed as a long
long timer_end(struct timespec start_time){
    struct timespec end_time = timer_start();

    long diffInNanos = end_time.tv_nsec - start_time.tv_nsec;
    return diffInNanos;
}

#endif // _WIN32

#ifdef _LINUX

// call this function to start a nanosecond-resolution timer
struct timespec timer_start(){
    struct timespec start_time;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start_time);
    return start_time;
}

// call this function to end a timer, returning nanoseconds elapsed as a long
long timer_end(struct timespec start_time){
    struct timespec end_time;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end_time);
    long diffInNanos = end_time.tv_nsec - start_time.tv_nsec;
    return diffInNanos;
}

#endif

bool gthread_mutex_lock(pthread_mutex_t* mutex)
{
    int err = pthread_mutex_lock(mutex);
    if(err == 0)
        return true;
    else if(err == EINVAL)
    {
        std::cout << "[GThread] Error locking mutex : "
                  << "The value specified by mutex does not refer to an initialised mutex object." << std::endl;
        return false;
    }
    else if(err == EAGAIN)
    {
        std::cout << "[GThread] Error locking mutex : "
                  << "The mutex could not be acquired because the maximum number of recursive locks for mutex has been exceeded." << std::endl;
        return false;
    }
    else if(err == EDEADLK)
    {
        std::cout << "[GThread] Error locking mutex : "
                  << "The current thread already owns the mutex." << std::endl;
        return false;
    }
    else
    {
        std::cout << "[GThread] Error locking mutex." << std::endl;
        return false;
    }
}

bool gthread_mutex_unlock(pthread_mutex_t* mutex)
{
    int err = pthread_mutex_unlock(mutex);
    if(err == 0)
        return true;
    else
    {
        std::cout << "[GThread] Error unlocking mutex." << std::endl;
        return false;
    }
}

static const char* __errors [GERROR_MAX] = {
    "No errors.",
    "Bad argues given.",
    "Can't open a file using standard io system.",
    "Buffer size has been exceeded.",
    "Can't read from a file.",
    "Invalid socket.",
    "Invalid host.",
    "Invalid connection.",
    "Can't send given packet to host.",
    "Can't close given socket.",
    "(Win) WSA can't start.",
    "Invalid binding of socket.",
    "Can't listen with given socket.",
    "Error creating thread.",
    "Error locking mutex.",
    "Error unlocking mutex.",
    "(Win) WSA can't be cleaned.",
    "Can't generate RSA key pair.",
    "Error in BIO functions.",
    "Error reading bio.",
    "Error writing encryption.",
    "Invalid Packet Type."
};

const char* gerror_to_string(gerror_t& err)
{
    size_t idx = (size_t) err;
    if(idx < GERROR_MAX)
        return __errors[idx];
    else
        return "";
}

gerror_t buffer_copy(buffer_t& dest, const buffer_t& src)
{
    dest.size = src.size;
    if(src.size > 0)
        memcpy(dest.buf, src.buf, src.size);

    return GERROR_NONE;
}

GEND_DECL
