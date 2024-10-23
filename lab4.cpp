#include "lab4.h"
#include <cctype>

std::string CaesarCipher::encrypt(const std::string &text, int key)
{
    std::string result;
    key = key % 26;

    for (char c : text)
    {
        if (std::isalpha(c))
        {
            char base = std::islower(c) ? 'a' : 'A';
            char encryptedChar = (c - base + key + 26) % 26 + base;
            result += encryptedChar;
        }
        else
        {
            result += c;
        }
    }
    return result;
}

std::string CaesarCipher::decrypt(const std::string &text, int key)
{
    return encrypt(text, -key);
}