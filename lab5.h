
#ifndef COLUMNAR_TRANSPOSITION_H 
#define COLUMNAR_TRANSPOSITION_H 
 
#include <string> 
 
class ColumnarTranspositionCipher 
{ 
public: 
    std::string encrypt(const std::string &message, int columns); 
 
    std::string decrypt(const std::string &ciphertext, int columns); 
 
private: 
    std::string padMessage(const std::string &message, int columns); 
}; 
 
#endif