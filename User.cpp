#include "User.h"
#include <string>

User::User(){
    User::userId;
    User::username;
    User::salt;
    User::password;
    User::enteredPassword;
}

User::User(int userId, std::string username, std::string salt, std::string password){
    User::userId = userId;
    User::username = username;
    User::salt = salt;
    User::password = password;
}

int User::getUserId(){
    return userId;
}

int User::setUserId(int userId){
    User::userId = userId;
    return User::userId;
}

std::string User::getUsername(){
    return username;
};
std::string User::setUsername(std::string username){
	User::username = username;
	return User::username;
};
        
std::string User::getSalt(){
    return salt;
};
std::string User::setSalt(std::string salt){
    User::salt = salt;
    return salt;
};
        
std::string User::getPassword(){
    return User::password;
};
std::string User::setPassword(std::string password){
    User::password = password;
    return User::password;
};

std::string User::getEnteredPassword(){
    return User::enteredPassword;
};
std::string User::setEnteredPassword(std::string enteredPassword){
    User::enteredPassword = enteredPassword;
    return User::enteredPassword;
};
