
#ifndef CAESAR_H 
#define CAESAR_H 
 
#include <string> 
 
class CaesarCipherBase 
{ 
public: 
    virtual std::string encrypt(const std::string &text, int key) = 0; 
    virtual std::string decrypt(const std::string &text, int key) = 0; 
    virtual ~CaesarCipherBase() = default; 
}; 
 
class CaesarCipher : public CaesarCipherBase 
{ 
public: 
    CaesarCipher() = default; 
    std::string encrypt(const std::string &text, int key) override; 
    std::string decrypt(const std::string &text, int key) override; 
}; 
 
#endif