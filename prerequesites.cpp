/*
    This file is part of the GangTella project
*/

#include "prerequesites.h"

GBEGIN_DECL

pthread_mutex_t __console_mutex = PTHREAD_MUTEX_INITIALIZER;
session_t globalsession;

FILE* _fileInfo = NULL;
FILE* _fileWarn = NULL;
FILE* _fileError = NULL;

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
timespec_t timer_start(){
    struct timespec start_time;

    struct timeval st_v;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &st_v);

    start_time.tv_sec  = st_v.tv_sec;
    start_time.tv_nsec = st_v.tv_usec * 1000;
    return start_time;
}

// call this function to end a timer, returning nanoseconds elapsed as a long
long timer_end(timespec_t start_time){
    struct timespec end_time = timer_start();

    long diffInNanos = end_time.tv_nsec - start_time.tv_nsec;
    return diffInNanos;
}

#endif // _WIN32

#if defined(_LINUX)

// call this function to start a nanosecond-resolution timer
timespec_t timer_start(){
    struct timespec start_time;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start_time);
    return start_time;
}

// call this function to end a timer, returning nanoseconds elapsed as a long
long timer_end(timespec_t start_time){
    struct timespec end_time;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end_time);
    long diffInNanos = end_time.tv_nsec - start_time.tv_nsec;
    return diffInNanos;
}

#endif

#if defined(_OSX)

// call this function to start a nanosecond-resolution timer
timespec_t timer_start(){
    timespec_t start_time = clock_gettime();
    return start_time;
}

// call this function to end a timer, returning nanoseconds elapsed as a long
long timer_end(timespec_t start_time){
    timespec_t end_time = clock_gettime();
    long diffInNanos = end_time - start_time;
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
        cout << "[GThread] Error locking mutex : "
                  << "The value specified by mutex does not refer to an initialised mutex object." << endl;
        return false;
    }
    else if(err == EAGAIN)
    {
        cout << "[GThread] Error locking mutex : "
                  << "The mutex could not be acquired because the maximum number of recursive locks for mutex has been exceeded." << endl;
        return false;
    }
    else if(err == EDEADLK)
    {
        cout << "[GThread] Error locking mutex : "
                  << "The current thread already owns the mutex." << endl;
        return false;
    }
    else
    {
        cout << "[GThread] Error locking mutex." << endl;
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
        cout << "[GThread] Error unlocking mutex." << endl;
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
    "Invalid Packet Type.",
    "No user database loaded.",
    "Can't create user keypass.",
    "Incorrect password given.",
    "Cipher requested not found.",
    "(OpenSSL) EVP_BytesToKey failed.",
    "Time out has expired.",
    "Network identifier not found in database.",
    "Network given invalid or null.",
    "Network already initialized.",
    "Sorry, feature not implemented for now.",
    "Bad user data given.",
    "(Win) Not suitable Windows Socket version.",
    "Can't allocate some memory.",
    "Packet answer is PT_RECEIVED_BAD. Errors occured during the reception of the packet.",
    "Can't have a valid answer packet.",
    "Database version is not the same as the program database interpreter.",
    "Database [autosave] flag has incorrect value.",
    "No OpenSSl could be initialized on this platform.",
    "Can't generate Public Key.",
    "No password provided for database.",
    "Can't find correct header in database.",
    "Can't decrypt database block.",
    "Database is bad encoded, or something is really wrong.",
    "No user provided.",
    "No user password provided.",
    "No packets have been received.",
    "(GCrypt) Bad Position token in file.",
    "No BT_USER block before BT_CLIENT block."
};

const char* gerror_to_string(GError err)
{
    size_t idx = (size_t) err;
    if(idx < GERROR_MAX)
        return __errors[idx];
    else
        return "";
}

const char* gerror_to_string(gerror_t err)
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

// From http://oopweb.com/CPP/Documents/CPPHOWTO/Volume/C++Programming-HOWTO-7.html
void Tokenize(const std::string& str,
              std::vector<std::string>& tokens,
              const std::string& delimiters)
{
    // Skip delimiters at beginning.
    std::string::size_type lastPos = str.find_first_not_of(delimiters, 0);
    // Find first "non-delimiter".
    std::string::size_type pos     = str.find_first_of(delimiters, lastPos);
    
    while (std::string::npos != pos || std::string::npos != lastPos)
    {
        // Found a token, add it to the vector.
        tokens.push_back(str.substr(lastPos, pos - lastPos));
        // Skip delimiters.  Note the "not_of"
        lastPos = str.find_first_not_of(delimiters, pos);
        // Find next "non-delimiter"
        pos = str.find_first_of(delimiters, lastPos);
    }
}

gerror_t NetworkInit()
{
#ifdef _WIN32
    
#ifdef GULTRA_DEBUG
    cout << "[Server] Starting WSA2.0." << endl;
#endif // GULTRA_DEBUG
    
    int err;
    WSAData wsadata;
    err = WSAStartup(MAKEWORD(2, 0), &wsadata);
    if(err == WSASYSNOTREADY)
    {
        cout << "[Server] Could not start Windows Socket : "
        << "The underlying network subsystem is not ready for network communication." << endl;
        return GERROR_WSASTARTUP;
    }
    else if(err == WSAVERNOTSUPPORTED)
    {
        cout << "[Server] Could not start Windows Socket : "
        << "The version of Windows Sockets support requested is not provided by this particular Windows Sockets implementation." << endl;
        return GERROR_WSASTARTUP;
    }
    else if(err == WSAEINPROGRESS)
    {
        cout << "[Server] Could not start Windows Socket : "
        << "A blocking Windows Sockets 1.1 operation is in progress." << endl;
        return GERROR_WSASTARTUP;
    }
    else if(err == WSAEPROCLIM)
    {
        cout << "[Server] Could not start Windows Socket : "
        << "A limit on the number of tasks supported by the Windows Sockets implementation has been reached." << endl;
        return GERROR_WSASTARTUP;
    }
    else if(err == WSAEFAULT)
    {
        cout << "[Server] Could not start Windows Socket : "
        << "The lpWSAData parameter is not a valid pointer." << endl;
        return GERROR_WSASTARTUP;
    }
    else if(LOBYTE(wsdata.wVersion) != 2 ||
            HIBYTE(wsdata.wVersion) != 0)
    {
        cout << "[Server] Invalid Windows Socket version. Could not found a suitable socket "
             << "implementation." << endl;
        WSACleanup();
        return GERROR_WSAVERSION;
    }
    
#endif // _WIN32
    
    return GERROR_NONE;
}

ssize_t grecv(int socket, void* buffer, size_t lenght, int flags)
{
    ssize_t ret = recv(socket, buffer, lenght, flags);
    if(ret == -1)
    {
        if(errno == EAGAIN ||
           errno == EWOULDBLOCK)
        {
            cout << "[grecv] No data is waiting to be received." << endl;
        }
        else if(errno == EBADF)
        {
            cout << "[grecv] Bad socket given !" << endl;
        }
        else if(errno == ETIMEDOUT)
        {
            cout << "[grecv] The connection timed out during connection establishment, "
                 << "or due to a transmission timeout on active connection." << endl;
        }
    }
    
    return ret;
}

#ifndef _WIN32

int getch() {
    int ch;
    struct termios t_old, t_new;
    
    tcgetattr(STDIN_FILENO, &t_old);
    t_new = t_old;
    t_new.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &t_new);
    
    ch = getchar();
    
    tcsetattr(STDIN_FILENO, TCSANOW, &t_old);
    return ch;
}

#endif

std::string getpass(bool show_asterisk)
{
#ifdef _WIN32 // Windows version
    
    const char BACKSPACE=8;
    const char RETURN=13;
    
    std::string password;
    unsigned char ch=0;
    
    DWORD con_mode;
    DWORD dwRead;
    
    HANDLE hIn=GetStdHandle(STD_INPUT_HANDLE);
    
    GetConsoleMode( hIn, &con_mode );
    SetConsoleMode( hIn, con_mode & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT) );
    
    while(ReadConsoleA( hIn, &ch, 1, &dwRead, NULL) && ch !=RETURN)
    {
        if(ch==BACKSPACE)
        {
            if(password.length()!=0)
            {
                if(show_asterisk)
                    cout <<"\b \b"; gthread_mutex_unlock(&__console_mutex);
                password.resize(password.length()-1);
            }
        }
        else
        {
            password+=ch;
            if(show_asterisk)
                cout <<'*'; gthread_mutex_unlock(&__console_mutex);
        }
    }
    cout << endl;
    return password;
    
#else // Unix version
    
    const char BACKSPACE=127;
    const char RETURN=10;
    
    std::string password;
    unsigned char ch=0;
    
    while((ch=getch())!=RETURN)
    {
        if(ch==BACKSPACE)
        {
            if(password.length()!=0)
            {
                if(show_asterisk)
                    cout <<"\b \b"; gthread_mutex_unlock(&__console_mutex);
                password.resize(password.length()-1);
            }
        }
        else
        {
            password+=ch;
            if(show_asterisk)
                cout <<'*'; gthread_mutex_unlock(&__console_mutex);
        }
    }
    cout << endl;
    return password;

#endif
}

void strbufcreateandcopy(char*& outstr, uint16_t& outlen, const char* in, uint16_t inlen)
{
    outstr = (char*) malloc(inlen+1);
    outlen = inlen;
    memcpy(outstr, in, inlen);
    outstr[inlen] = '\0';
}

netbuffer_t* netbuf_new(uint16_t lenght)
{
    netbuffer_t* ret = (netbuffer_t*) malloc(sizeof(netbuffer_t));
    
    if(!ret) {
#ifdef GULTRA_DEBUG
        cout << "[netbuf] Can't allocate netbuffer structure." << endl;
        exit(GERROR_ALLOC);
#endif
        
        return ret;
    }
    
    ret->lenght = 0;
    
    if(lenght > 0)
    {
        ret->buf    = (char*) malloc(lenght + 1);
        
        if(!ret->buf) {
#ifdef GULTRA_DEBUG
            cout << "[netbuf] Can't allocate netbuffer data." << endl;
            exit(GERROR_ALLOC);
#endif
            return ret;
        }
        
        ret->buf[lenght] = '\0';
        ret->lenght      = lenght;
    }
    else
    {
        ret->buf = nullptr;
    }
    
    return ret;
}

netbuffer_t* netbuf_copy(const netbuffer_t& other)
{
    netbuffer_t* ret = (netbuffer_t*) malloc(sizeof(netbuffer_t));
    
    if(!ret) {
#ifdef GULTRA_DEBUG
        cout << "[netbuf] Can't allocate netbuffer structure." << endl;
        exit(GERROR_ALLOC);
#endif
        
        return ret;
    }
    
    ret->lenght = 0;
    
    if(other.lenght > 0)
    {
        ret->buf    = (char*) malloc(other.lenght + 1);
        
        if(!ret->buf) {
#ifdef GULTRA_DEBUG
            cout << "[netbuf] Can't allocate netbuffer data." << endl;
            exit(GERROR_ALLOC);
#endif
            return ret;
        }
        
        memcpy(ret->buf, other.buf, other.lenght);
        ret->buf[other.lenght] = '\0';
        ret->lenght            = other.lenght;
    }
    else
    {
        ret->buf = nullptr;
    }
    
    return ret;
}

void netbuf_copyraw(netbuffer_t* to, const char* from, uint16_t lenght)
{
    if(to->lenght > 0 || to->buf != nullptr) {
#ifdef GULTRA_DEBUG
        cout << "[netbuf] netbuffer structure not empty, so deleting it." << endl;
#endif
        netbuf_delete(to);
    }
    
    if(from && lenght > 0)
    {
        to->buf = (char*) malloc(lenght);
        if(!to->buf) {
#ifdef GULTRA_DEBUG
            cout << "[netbuf] Can't allocate netbuffer data." << endl;
            exit(GERROR_ALLOC);
#endif
            return;
        }
        
        memcpy(to->buf, from, lenght);
        to->buf[lenght] = '\0';
        to->lenght      = lenght;
    }
    else
    {
        to->lenght = 0;
        to->buf    = nullptr;
    }
}

void netbuf_delete(netbuffer_t* buf)
{
    if(buf->lenght > 0)
    {
        free(buf->buf);
    }
    
    buf->lenght = 0;
    buf->buf    = nullptr;
}

void netbuf_free(netbuffer_t*& buf)
{
    netbuf_delete(buf);
    free(buf);
    buf = nullptr;
}

netbuffer_t* netbuf_new(const char* data, uint16_t lenght)
{
    netbuffer_t* ret = netbuf_new(0);
    if(ret)
        netbuf_copyraw(ret, data, lenght);
    return ret;
}

void gnotifiate (int level, const char* format, ...)
{
    if(!_fileInfo || !_fileWarn || !_fileError) {
        _fileInfo = _fileWarn = _fileError = stdout;
    }
    
    va_list args;
    FILE* log_file = level == 0 ? _fileError : level == 1 ? _fileWarn : _fileInfo;
    
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);
    
#if GULTRA_DEBUG
    fflush(log_file);
    fsync(fileno(log_file));
#endif
}

void gnotifiate_setloglevelfile(int level, FILE* file)
{
    if(level == 0)
        _fileError = file;
    else if(level == 1)
        _fileWarn = file;
    else
        _fileInfo = file;
}

GEND_DECL
