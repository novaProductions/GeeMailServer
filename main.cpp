#include <stdio.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <sqlite3.h>

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
    db = executeSqlQueryNoParams("CREATE TABLE USERS( ID INT PRIMARY KEY, USERNAME  TEXT, SALT INT, PASSWORD TEXT );", db);
    db = executeSqlQueryNoParams("CREATE TABLE MESSAGES( ID INT PRIMARY KEY, TIMESTAMP INT, SENDER INT, RECEIVER INT, MESSAGE TEXT);", db);
    
    sqlite3_close(db);
}

void addNewUser(){
    sqlite3* db;
    char username [30];
    char password [30];
    
    cout << "Enter Username (Max Size 30 Characters):";
    cin >> setw(31) >> username;

    cout << "Enter Password (Max Size 30 Characters):";
    cin >> setw(31) >> password;
    
    db = openDatabase(db);
    
    char *zErrMsg = 0;
    sqlite3_stmt *stmt;
    const char *pzTest;
    char *szSQL;

    szSQL = "insert into USERS (ID, USERNAME, SALT, PASSWORD) values (?,?,?,?)";

    int rc = sqlite3_prepare(db, szSQL, 65, &stmt, &pzTest);

    if( rc == SQLITE_OK ) {
        // bind the value 
        sqlite3_bind_int(stmt, 1, 3);
        sqlite3_bind_text(stmt, 2, username, 30, 0);
        sqlite3_bind_int(stmt, 3, 54325);
        sqlite3_bind_text(stmt, 4, password, 30, 0);
        

        // commit 
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    
        sqlite3_close(db);
    }
}


int main(){
    createDatabase();
    addNewUser();
};