#include "lab6.h" 
#include <stdexcept> 
#include <sstream> 
 
std::string RunLengthEncoding::encode(const std::string &input) 
{ 
    if (input.empty()) 
        return ""; 
 
    std::ostringstream encoded; 
    int length = input.length(); 
 
    for (int i = 0; i < length; ++i) 
    { 
        char currentChar = input[i]; 
        int count = 1; 
 
        while (i + 1 < length && input[i] == input[i + 1]) 
        { 
            ++count; 
            ++i; 
        } 
 
        encoded << currentChar << count; 
    } 
 
    return encoded.str(); 
} 
 
std::string RunLengthEncoding::decode(const std::string &input) 
{ 
    if (input.empty()) 
        return ""; 
 
    std::ostringstream decoded; 
    int length = input.length(); 
 
    for (int i = 0; i < length; ++i) 
    { 
        char character = input[i]; 
 
        if (i + 1 >= length || !isdigit(input[i + 1])) 
        { 
            throw std::invalid_argument("Invalid encoded input: Missing or incorrect count value."); 
        } 
 
        int count = 0; 
        while (i + 1 < length && isdigit(input[i + 1])) 
        { 
            count = count * 10 + (input[++i] - '0'); 
        } 
 
        decoded << std::string(count, character); 
    } 
 
    return decoded.str(); 
}