#include "lab5.h"
#include <iostream>
#include <algorithm>
#include <vector>

std::string ColumnarTranspositionCipher::padMessage(const std::string &message, int columns)
{
    std::string paddedMessage = message;
    while (paddedMessage.length() % columns != 0)
    {
        paddedMessage += 'X';
    }
    return paddedMessage;
}

std::string ColumnarTranspositionCipher::encrypt(const std::string &message, int columns)
{
    std::string paddedMessage = padMessage(message, columns);
    int rows = paddedMessage.length() / columns;
    std::vector<std::string> grid(rows);

    for (int i = 0; i < rows; ++i)
    {
        grid[i] = paddedMessage.substr(i * columns, columns);
    }

    std::string ciphertext;
    for (int col = 0; col < columns; ++col)
    {
        for (int row = 0; row < rows; ++row)
        {
            ciphertext += grid[row][col];
        }
    }

    return ciphertext;
}

std::string ColumnarTranspositionCipher::decrypt(const std::string &ciphertext, int columns)
{
    int rows = ciphertext.length() / columns;
    std::vector<std::string> grid(rows);

    int k = 0;
    for (int col = 0; col < columns; ++col)
    {
        for (int row = 0; row < rows; ++row)
        {
            grid[row] += ciphertext[k++];
        }
    }

    std::string plaintext;
    for (int row = 0; row < rows; ++row)
    {
        plaintext += grid[row];
    }

    plaintext.erase(std::remove(plaintext.begin(), plaintext.end(), 'X'), plaintext.end());

    return plaintext;
}