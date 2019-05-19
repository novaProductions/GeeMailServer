#include <stdio.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <sqlite3.h>
#include <openssl/sha.h>
#include "User.h"

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
    db = executeSqlQueryNoParams("CREATE TABLE messages(message_id INTEGER PRIMARY KEY, timestamp INTEGER, sender INTEGER, reciever INTEGER, message TEXT);", db);
    
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

void mainMenu(User user){
    string optionSeletected;
    cout << "Hello, " + user.getUsername() + " you are logged in" << endl;
    cout << "Enter number for the option you want:" << endl;
    cout << "1 - Send Message" << endl;
    cout << "2 - View Messages" << endl;
    cout << "3 - Create New User" << endl;
    cout << "4 - Logout" << endl;
    getline(cin, optionSeletected);
    while (optionSeletected != "1" && optionSeletected != "2" && optionSeletected != "3" && optionSeletected != "4") {
        cout << "That is not a valid option. try again" << endl;
        getline(cin, optionSeletected);
    }
}

void startingMenu(){
    string optionSeletected;
    cout << "Enter number for the option you want:" << endl;
    cout << "1 - Login" << endl;
    cout << "2 - Create New User" << endl;
    getline(cin, optionSeletected);
    while (optionSeletected != "1" && optionSeletected != "2") {
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
    }
}

int main(){
    srand(time(NULL));
    createDatabase();
    startingMenu();

    
    
    
};