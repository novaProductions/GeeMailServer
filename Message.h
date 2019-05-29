#pragma once
#include <string>


class Message{
    public:
        Message();
        Message(int messageId, int senderId, int recieverId, std::string message);
        
        int getMessageId();
        int setMessageId(int messageId);

        int getSenderId();
        int setSenderId(int senderId);
        
        int getRecieverId();
        int setRecieverId(int recieverId);
        
        std::string getIv();
        std::string setIv(std::string iv);
        
        std::string getMessage();
        std::string setMessage(std::string message);
    
    private:
        int messageId;
        int senderId;
        int recieverId;
        std::string iv;
        std::string message;
};