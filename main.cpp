#include <stdio.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <sqlite3.h>
#include <openssl/sha.h>
#include <vector>
#include <gcrypt.h>
#include "User.h"
#include "Message.h"
#include <bitset>

using namespace std;

static int callback(void *NotUsed, int argc, char **argv, char **azColName){
    int i;
    for(i=0; i<argc; i++){
        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    printf("\n");
    return 0;
}

sqlite3* openDatabase(sqlite3* db){
    int rc;
    
    rc = sqlite3_open("mail.db", &db);
    if( rc ){
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
    };
    return db;
}

sqlite3* executeSqlQueryNoParams(char* sql, sqlite3* db) {
    char *zErrMsg = 0;
    int rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    if( rc != SQLITE_OK ){
    fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    }
    return db;
}


void createDatabase(){
    sqlite3* db;

    db = openDatabase(db);
    db = executeSqlQueryNoParams("CREATE TABLE users(user_id INTEGER PRIMARY KEY, username  TEXT, salt TEXT, password TEXT);", db);
    db = executeSqlQueryNoParams("CREATE TABLE messages(message_id INTEGER PRIMARY KEY, sender INTEGER, reciever INTEGER, message TEXT, iv TEXT);", db);
    
    sqlite3_close(db);
}

string sha256(const string str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

string genSalt(){
    long max = 999999999999999999;
    long min = 100000000000000000;
    return to_string(rand() %  max + min);
}

void saveNewUserToDb(string username, string password){
    
    string salt = genSalt();
    sqlite3* db;
    db = openDatabase(db);
    
    char *zErrMsg = 0;
    sqlite3_stmt *stmt;
    const char *pzTest;
    char *szSQL;

    szSQL = "INSERT INTO users (username, salt, password) VALUES (?,?,?)";

    int rc = sqlite3_prepare(db, szSQL, 65, &stmt, &pzTest);

    if( rc == SQLITE_OK ) {
        // bind the value 
        string hashPassword = sha256(salt + password);
        sqlite3_bind_text(stmt, 1, username.c_str(), username.size(), 0);
        sqlite3_bind_text(stmt, 2, salt.c_str(), salt.size(), 0);
        sqlite3_bind_text(stmt, 3, hashPassword.c_str(), hashPassword.size(), 0);

        // commit 
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    
        sqlite3_close(db);
    }
    
}

int checkForExistingUser(string username){
    
    sqlite3* db;
    db = openDatabase(db);
    
    char *zErrMsg = 0;
    sqlite3_stmt *stmt;
    const char *pzTest;
    char *szSQL;

    szSQL = "SELECT COUNT(*) FROM users WHERE username = (?)";
    
    int rc = sqlite3_prepare(db, szSQL, 47, &stmt, &pzTest);
    int numOfMatchingNames = 1;
    
    if( rc == SQLITE_OK ) {
        // bind the value 
        sqlite3_bind_text(stmt, 1, username.c_str(), username.size(), 0);

        // commit 
        sqlite3_step(stmt);
        numOfMatchingNames = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
    
        sqlite3_close(db);
    }
    return numOfMatchingNames;
}


User getUsersInfo(string username){
    
    sqlite3* db;
    db = openDatabase(db);
    
    char *zErrMsg = 0;
    sqlite3_stmt *stmt;
    const char *pzTest;
    char *szSQL;

    szSQL = "SELECT * FROM users WHERE username = (?)";
    
    int rc = sqlite3_prepare(db, szSQL, 47, &stmt, &pzTest);
    
    User currentUser;
    
    if( rc == SQLITE_OK ) {
        // bind the value 
        sqlite3_bind_text(stmt, 1, username.c_str(), username.size(), 0);

        // commit 
        sqlite3_step(stmt);
        
        
        if(sqlite3_column_type(stmt, 0) != SQLITE_NULL){
            currentUser.setUserId(sqlite3_column_int(stmt, 0));
            currentUser.setUsername(string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1))));
            currentUser.setUsername(string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1))));
            currentUser.setSalt(string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2))));
            currentUser.setPassword(string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3))));
        }

        sqlite3_finalize(stmt);
    
        sqlite3_close(db);
    }
    
    return currentUser;
}
void addNewUser(){
    
    string username;
    string password;
    
    cout << "Enter Username (Max Size 30 Characters):";
    getline(cin, username);
    while (username.length() > 30) {
        cout << "Username is to long. try again" << endl;
        getline(cin, username);
    }
    
    while (checkForExistingUser(username) != 0) {
        cout << "Username is already used. try again" << endl;
        getline(cin, username);
    }
    
    cout << "Enter Password (Max Size 30 Characters):";
    getline(cin, password);
    while (password.length() > 30) {
        cout << "Password is to long. try again" << endl;
        getline(cin, password);
    }
    
    saveNewUserToDb(username, password);
    
    cout << "Created User: " + username << endl;
}

User userInputLoginCreds(){
    string username;
    string enteredPassword;
    
    cout << "Enter Username (Max Size 30 Characters):";
    getline(cin, username);
    while (username.length() > 30) {
        cout << "Username is to long. try again" << endl;
        getline(cin, username);
    }
    
    cout << "Enter Password (Max Size 30 Characters):";
    getline(cin, enteredPassword);
    while (enteredPassword.length() > 30) {
        cout << "Password is to long. try again" << endl;
        getline(cin, enteredPassword);
    }
    
    User currentUSer = getUsersInfo(username);
    currentUSer.setEnteredPassword(enteredPassword);
    
    return currentUSer;
}

User Login(){

    User currentUser = userInputLoginCreds();
    while(sha256(currentUser.getSalt() + currentUser.getEnteredPassword()) != currentUser.getPassword()){
        cout << "User name and password did not match. try again" << endl;
        currentUser = userInputLoginCreds();
    }
    return currentUser;
}

void saveMessageToDb(int senderId, int recieverId, string message, string iv){
    
    sqlite3* db;
    db = openDatabase(db);
    
    char *zErrMsg = 0;
    sqlite3_stmt *stmt;
    const char *pzTest;
    char *szSQL;

    szSQL = "INSERT INTO messages (sender, reciever, message, iv) VALUES (?,?,?,?)";

    int rc = sqlite3_prepare(db, szSQL, 69, &stmt, &pzTest);

    if( rc == SQLITE_OK ) {
        // bind the value 
        sqlite3_bind_int(stmt, 1, senderId);
        sqlite3_bind_int(stmt, 2, recieverId);
        sqlite3_bind_text(stmt, 3, message.c_str(), message.size(), 0);
        sqlite3_bind_text(stmt, 4, iv.c_str(), iv.size(), 0);

        // commit 
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    
        sqlite3_close(db);
    }
    
}

gcry_cipher_hd_t setUpCipher(char * sym_key, const char * init_vector){
    #define GCRY_CIPHER GCRY_CIPHER_AES256   // Pick the cipher here
    
    int gcry_mode=GCRY_CIPHER_MODE_CBC;
    
    gcry_error_t     gcry_ret;
    gcry_cipher_hd_t cipher_hd;

    if (!gcry_control (GCRYCTL_ANY_INITIALIZATION_P)) {
        gcry_check_version(NULL); /* before calling any other functions */
    }

    gcry_ret = gcry_cipher_open(
        &cipher_hd,    // gcry_cipher_hd_t *hd
        GCRY_CIPHER,   // int algo
        gcry_mode,     // int mode
        0);            // unsigned int flags
    if (gcry_ret) {
        printf("gcry_cipher_open failed:  %s/%s\n",
                gcry_strsource(gcry_ret), gcry_strerror(gcry_ret));
        return cipher_hd;
    }

    size_t key_length = gcry_cipher_get_algo_keylen(GCRY_CIPHER);
    gcry_ret = gcry_cipher_setkey(cipher_hd, sym_key, key_length);
    if (gcry_ret) {
        printf("gcry_cipher_setkey failed:  %s/%s\n",
                gcry_strsource(gcry_ret), gcry_strerror(gcry_ret));
        return cipher_hd;
    }

    size_t blk_length = gcry_cipher_get_algo_blklen(GCRY_CIPHER);
    gcry_ret = gcry_cipher_setiv(cipher_hd, init_vector, blk_length);
    if (gcry_ret) {
        printf("gcry_cipher_setiv failed:  %s/%s\n",
                gcry_strsource(gcry_ret), gcry_strerror(gcry_ret));
        return cipher_hd;
    }
    return cipher_hd;
}

string encrypt(string plaintxt, char * sym_key, const char * init_vector)
{
    #define GCRY_CIPHER GCRY_CIPHER_AES256   // Pick the cipher here
    int plaintxt_length = 320;
	
    gcry_error_t     gcry_ret;
    gcry_cipher_hd_t cipher_hd = setUpCipher(sym_key, init_vector);

    char * plaintxtBuffer = new char[plaintxt_length];
    copy(plaintxt.begin(), plaintxt.end(), plaintxtBuffer);
    plaintxtBuffer[plaintxt.size()] = '\0'; 

    char * encrypted_txt = (char *)malloc(plaintxt_length);
    gcry_ret = gcry_cipher_encrypt(
        cipher_hd,         // gcry_cipher_hd_t h
        encrypted_txt,      // unsigned char *out
        plaintxt_length,   // size_t outsize
        plaintxtBuffer,          // const unsigned char *in
        plaintxt_length);  // size_t inlen
    string encrypted_txt_str = encrypted_txt;
    if (gcry_ret) {
        printf("gcry_cipher_encrypt failed:  %s/%s\n",
                gcry_strsource(gcry_ret), gcry_strerror(gcry_ret));
        return encrypted_txt_str;
    }

    // clean up
    gcry_cipher_close(cipher_hd);
    return encrypted_txt_str;
}

string decrypt(string encrypted_txt_str, char * sym_key, const char * init_vector)
{
    #define GCRY_CIPHER GCRY_CIPHER_AES256   // Pick the cipher here
    int plaintxt_length = 320;
	
    gcry_error_t     gcry_ret;
    gcry_cipher_hd_t cipher_hd = setUpCipher(sym_key, init_vector);

    char * encrypted_txt = new char[plaintxt_length];
    copy(encrypted_txt_str.begin(), encrypted_txt_str.end(), encrypted_txt);
    encrypted_txt[encrypted_txt_str.size()] = '\0'; 

    char * decrpyted_txt = (char *)malloc(plaintxt_length);
    
    gcry_ret = gcry_cipher_decrypt(
        cipher_hd,          // gcry_cipher_hd_t h
        decrpyted_txt,      // unsigned char *out
        plaintxt_length,    // size_t outsize
        encrypted_txt,       // const unsigned char *in
        plaintxt_length);   // size_t inlen
    string decrypted_txt_str = decrpyted_txt;
    if (gcry_ret) {
        printf("gcry_cipher_decrypt failed:  %s/%s\n",
                gcry_strsource(gcry_ret), gcry_strerror(gcry_ret));
        return decrypted_txt_str;
    }

    // clean up
    gcry_cipher_close(cipher_hd);
    return decrypted_txt_str;
}

void sendMessage(User user){
    string username;
    string message;
    char * key = (char*)calloc(32,sizeof(char));
    string iv = genSalt();
    
    cout << "Who Do You Want To Send A Message To? (Valid Username):" << endl;
    getline(cin, username);
    while (checkForExistingUser(username) != 1) {
        cout << "User is not found. Try again" << endl;
        getline(cin, username);
    }
    
    User reciever = getUsersInfo(username);
    cout << "Type your message (Under 300 characters)" << endl;
    
    getline(cin, message);
    while (message.length() > 300) {
        cout << "Message is to large max is 300 characters" << endl;
        getline(cin, message);
    }
    
    cout << "Enter the key used to protect your message? (min 16- max 32 characters):" << endl;
    while (strlen(key) > 32) {
        cout << "Key must be under 32 characters" << endl;
        cin.getline(key, 32);
    }
    while (strlen(key) < 16) {
        cout << "Key must be above 16 characters" << endl;
        cin.getline(key, 32);
    }
    
    string encryptedMessage = encrypt(message, key, iv.c_str());
    saveMessageToDb(user.getUserId(), reciever.getUserId(), encryptedMessage, iv);
    
    string optionSeletected;
    cout << "Enter number for the option you want:" << endl;
    cout << "1 - Send Message" << endl;
    cout << "2 - Exit And Logout" << endl;
    getline(cin, optionSeletected);
    while (optionSeletected != "1" && optionSeletected != "2") {
        cout << "That is not a valid option. try again" << endl;
        getline(cin, optionSeletected);
    }
    if(optionSeletected == "1"){
        cout << "Send Message - Selected" << endl;
        sendMessage(user);
    }else if(optionSeletected == "2"){
        cout << "Exit And Logout - Selected" << endl;
    }
}

vector<Message> getConversation(int currentUserId, int otherPartyId){
    
    sqlite3* db;
    db = openDatabase(db);
    
    char *zErrMsg = 0;
    sqlite3_stmt *stmt;
    const char *pzTest;
    char *szSQL;

    szSQL = "SELECT * FROM messages WHERE (sender = (?) AND reciever = (?)) OR (sender = (?) AND reciever = (?))";
    
    int rc = sqlite3_prepare(db, szSQL, 99, &stmt, &pzTest);
    
    
    vector<Message> conversation;
    
    if( rc == SQLITE_OK ) {
        // bind the value 
        sqlite3_bind_int(stmt, 1, currentUserId);
        sqlite3_bind_int(stmt, 2, otherPartyId);
        sqlite3_bind_int(stmt, 3, otherPartyId);
        sqlite3_bind_int(stmt, 4, currentUserId);

        // commit 
        ;
        
        while(sqlite3_step(stmt) != 101){
            if(sqlite3_column_type(stmt, 0) != SQLITE_NULL){
            Message message;
            message.setMessageId(sqlite3_column_int(stmt, 0));
            message.setSenderId(sqlite3_column_int(stmt, 1));
            message.setRecieverId(sqlite3_column_int(stmt, 2));
            message.setMessage(string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3))));
            message.setIv(string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4))));
            conversation.push_back(message);
            }
        }

        sqlite3_finalize(stmt);
    
        sqlite3_close(db);
    }
    return conversation;
}

void viewMessages(User user){
    string username;
    char * key = (char*)calloc(32,sizeof(char));
    
    cout << "Who's messages do you want to view? (Valid Username):" << endl;
    getline(cin, username);
    while (checkForExistingUser(username) != 1) {
        cout << "User 1 not found. Try again" << endl;
        getline(cin, username);
    }
    User targetUser = getUsersInfo(username);
    
    vector<Message> conversation = getConversation(user.getUserId(), targetUser.getUserId());
    
    if(conversation.size() == 0){
        cout << "You have not recieved or sent messages from/to this user" << endl;
    }else{
        cout << "Enter the key used to protect your message:" << endl;
        cin >> key;
    
        for(int i=0; i < conversation.size(); i++){
            string senderUsername;
            if(user.getUserId() == conversation[i].getSenderId()){
                senderUsername = user.getUsername();
            }
            else(targetUser.getUserId() == conversation[i].getSenderId());{
                senderUsername = targetUser.getUsername();
            }
            
            string iv = conversation[i].getIv();
            
            string decryptedMessage = decrypt(conversation[i].getMessage(), key, iv.c_str());
            cout << senderUsername + " : " + decryptedMessage << endl;
        }
    }
    

    
    string optionSeletected;
    cout << "Enter number for the option you want:" << endl;
    cout << "1 - View More Messages" << endl;
    cout << "2 - Exit And Logout" << endl;
    getline(cin, optionSeletected);
    while (optionSeletected != "1" && optionSeletected != "2") {
        cout << "That is not a valid option. try again" << endl;
        getline(cin, optionSeletected);
    }
    if(optionSeletected == "1"){
        cout << "View More Messages - Selected" << endl;
        viewMessages(user);
    }else if(optionSeletected == "2"){
        cout << "Exit And Logout - Selected" << endl;
    }
}

void mainMenu(User user){
    string optionSeletected;
    cout << "Hello, " + user.getUsername() + " you are logged in" << endl;
    cout << "Enter number for the option you want:" << endl;
    cout << "1 - Send Message" << endl;
    cout << "2 - View Messages" << endl;
    cout << "3 - Create New User" << endl;
    cout << "4 - Exit And Logout" << endl;
    getline(cin, optionSeletected);
    while (optionSeletected != "1" && optionSeletected != "2" && optionSeletected != "3" && optionSeletected != "4") {
        cout << "That is not a valid option. try again" << endl;
        getline(cin, optionSeletected);
    }
    
    if(optionSeletected == "1"){
        cout << "Send Message - Selected" << endl;
        sendMessage(user);
    }else if(optionSeletected == "2"){
        cout << "View Message - Selected" << endl;
        viewMessages(user);
    }else if(optionSeletected == "3"){
        cout << "Create New User - Selected" << endl;
        addNewUser();
        mainMenu(user);
    }else if(optionSeletected == "4"){
        cout << "Exit And Logout - Selected" << endl;
    }
}

void startingMenu(){
    string optionSeletected;
    cout << "Enter number for the option you want:" << endl;
    cout << "1 - Login" << endl;
    cout << "2 - Create New User" << endl;
    cout << "3 - Exit" << endl;
    getline(cin, optionSeletected);
    while (optionSeletected != "1" && optionSeletected != "2" && optionSeletected != "3") {
        cout << "That is not a valid option. try again" << endl;
        getline(cin, optionSeletected);
    }
    
    if(optionSeletected == "1"){
        cout << "Login - Selected" << endl;
        User currentUser = Login();
        mainMenu(currentUser);
    }else if(optionSeletected == "2"){
        cout << "Create New User - Selected" << endl;
        addNewUser();
        startingMenu();
    }else if(optionSeletected == "3"){
        cout << "Exit - Selected" << endl;
    }
}

int main(){
    srand(time(NULL));
    createDatabase();
    
    string message = "some data";
    string iv = "100000000230179139";
    string key = "keykeykeykeykeykey";
    //cout << decrypt(encrypt(message, key.c_str(), iv.c_str()), key.c_str(), iv.c_str()) << endl;

    startingMenu();
    
};