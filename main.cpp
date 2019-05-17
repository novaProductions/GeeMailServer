#include <stdio.h>
#include <iostream>
#include <sqlite3.h>

static int callback(void *NotUsed, int argc, char **argv, char **azColName){
    int i;
    for(i=0; i<argc; i++){
        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    printf("\n");
    return 0;
}

sqlite3* executeSqlQuery(char* sql, sqlite3* db) {
    char *zErrMsg = 0;
    int rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    if( rc != SQLITE_OK ){
    fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
    }
    return db;
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

void createDatabase(){
    sqlite3* db;

    db = openDatabase(db);
    db = executeSqlQuery("CREATE TABLE USERS( ID INT PRIMARY KEY, USERNAME  TEXT, SALT INT, PASSWORD TEXT );", db);
    db = executeSqlQuery("CREATE TABLE MESSAGES( ID INT PRIMARY KEY, TIMESTAMP INT, SENDER INT, RECEIVER INT, MESSAGE TEXT);", db);
    
    sqlite3_close(db);
}



int main(){
    createDatabase();

};