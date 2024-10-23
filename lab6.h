#ifndef RLE_H 
#define RLE_H 
 
#include <string> 
 
class RunLengthEncoding 
{ 
public: 
    std::string encode(const std::string &input); 
    std::string decode(const std::string &input); 
}; 
 
#endif