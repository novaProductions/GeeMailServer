#pragma once
#include <string>

class User 
{
    public:
        User();
        User(std::string username, std::string salt, std::string password);
        
        std::string getUsername();
        std::string setUsername(std::string username);
        
        std::string getSalt();
        std::string setSalt(std::string salt);
        
        std::string getPassword();
        std::string setPassword(std::string password);
        
        std::string getEnteredPassword();
        std::string setEnteredPassword(std::string enteredPassword);
    private: 
        std::string username;
        std::string salt;
        std::string password;
        std::string enteredPassword;
};