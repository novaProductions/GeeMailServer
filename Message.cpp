#include "Message.h"
#include <string>

Message::Message(){
    Message::messageId;
    Message::senderId;
    Message::recieverId;
    Message::message;
};
Message::Message(int messageId, int senderId, int recieverId, std::string message){
    Message::messageId = messageId;
    Message::senderId = senderId;
    Message::recieverId = recieverId;
    Message::message = message;
};
        
int Message::getMessageId(){
    return messageId;
};
int Message::setMessageId(int messageId){
    Message::messageId = messageId;
    return Message::messageId;
};

int Message::getSenderId(){
    return senderId;
};
int Message::setSenderId(int senderId){
    Message::senderId = senderId;
    return Message::senderId;
};
        
int Message::getRecieverId(){
    return recieverId;
};
int Message::setRecieverId(int recieverId){
    Message::recieverId = recieverId;
    return Message::recieverId;
};
        
std::string Message::getMessage(){
    return message;
};
std::string Message::setMessage(std::string message){
    Message::message = message;
    return Message::message;
};
