
///////////////////////////////////////////////////////
///
/// @brief A pair with its key and iv value.
///
///////////////////////////////////////////////////////
typedef struct {
    
    std::string key;
    std::string iv;
    
} keypair_t;

///////////////////////////////////////////////////////
///
/// @brief Stores info about a client.
///
///////////////////////////////////////////////////////
typedef struct database_clientinfo_t {
    
    std::string ip;
    uint16_t    port;
    
    database_clientinfo_t() : ip(""), port(0) {
        
    }
    
} database_clientinfo_t;

typedef struct database_accepted_user_t {
    std::string name;
    keypair_t   keys;
    
    database_accepted_user_t() : name(""), keys() {
 
    }
    
} database_accepted_user_t;

struct database_user_t {
  
    /*
    char* name;
    char* key;
    char* iv;
    
    uint16_t lname;
    uint16_t lkey;
    uint16_t liv;
     */
    
    netbuffer_t* m_name;
    netbuffer_t* m_key;
    netbuffer_t* m_iv;
    
    stat_t status;
    
    std::vector<database_clientinfo_t> clients;
    std::vector<database_accepted_user_t> acceptedusers;
    
    database_user_t() : m_name(nullptr), m_key(nullptr), m_iv(nullptr), status(0.0f) {
        
    }
    
    bool operator == (const database_user_t& rhs) {
        return strcmp(m_name->buf, rhs.m_name->buf) == 0;
    }
    
};

typedef struct database_t {
   
    /*
    char* name;
    uint16_t lname;
     */
    netbuffer_t* m_name;
    
    std::string key;
    std::string iv;
    std::string path;
    
    std::vector <database_user_t*> data;
    
    database_t() : m_name(nullptr) {
        
    }
    
} database_t;

typedef database_clientinfo_t dbclient_t;
typedef dbclient_t* dbclientptr_t;
typedef std::vector<dbclientptr_t> dbclientlist_t;

template <> std::string to_text(const dbclientlist_t& clist);
template <> dbclientlist_t from_text(const std::string& clist);

typedef database_user_t user_t;
typedef user_t* userptr_t;
typedef std::map<std::string, userptr_t> userbyname_t;





