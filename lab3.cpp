#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <Windows.h>
#include <WinCrypt.h>

#define BLOCK_LENGTH 4097 // Размер буфера 4КБ
#define CALG_G28147 26142 // Алгоритм шифрования

HCRYPTPROV hProv;        // Дескриптор криптопровайдера
HCRYPTKEY hSessionKey;   // Дескриптор сессионного ключа
HCRYPTKEY hDuplicateKey; // Дескриптор дубликата сессионного ключа
DWORD hProvType = (DWORD)80;

int main()
{
    BYTE pbContent[BLOCK_LENGTH] = {0}; // Указатель на содержимое исходного файла
    DWORD cbContent = 0;                // Длина содержимого
    DWORD bufLen = sizeof(pbContent);
    char pin[] = "sys";

    if (CryptAcquireContext(
            &hProv,
            (LPCWSTR)L"Cache",
            (LPCWSTR)L"Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider",
            hProvType,
            CRYPT_SILENT))
    {
        CryptSetProvParam(hProv, PP_SIGNATURE_PIN, (LPBYTE)pin, 0);
    }
    else
    {
        printf("\nError AcquireContext\n");
        return 1;
    }

    if (!CryptGenKey(hProv, CALG_G28147, CRYPT_ENCRYPT | CRYPT_DECRYPT, &hSessionKey))
    {
        printf("Session key does not generated.\n");
    }

    FILE *file = fopen("test.txt", "r");
    if (!file)
    {
        printf("Unable to open file");
        return 1;
    }

    FILE *Encrypt = fopen("encrypt.bin", "wb");
    if (!Encrypt)
    {
        printf("Unable to open Encrypt file");
        return 1;
    }

    do
    {
        if (!CryptDuplicateKey(hSessionKey, NULL, 0, &hDuplicateKey))
        {
            printf("The session key does not duplicated.\n");
        }
        memset(pbContent, 0, sizeof(pbContent));
        cbContent = (DWORD)fread(pbContent, 1, BLOCK_LENGTH - 1, file);
        pbContent[cbContent] = '\0';

        printf("String: %s   syze is %d\n", pbContent, cbContent);

        if (cbContent)
        {
            BOOL bFinal = feof(file);
            // Зашифрование прочитанного блока на сессионном ключе.
            if (CryptEncrypt(hDuplicateKey, 0, bFinal, 0, (BYTE *)pbContent, &cbContent, bufLen))
            {
                // Запись зашифрованного блока в файл.
                if (!fwrite(pbContent, 1, cbContent, Encrypt))
                {
                    printf("The encrypted content can not be written to the 'encrypt.bin'\n");
                }
            }
            else
            {
                printf("Encryption failed.");
            }
            if (CryptDecrypt(hSessionKey, 0, bFinal, 0, (BYTE *)pbContent, &cbContent))
                printf("\nDecrypt is: %s\n", pbContent);
        }
        else
        {
            printf("Problem reading the file 'test.txt'\n");
        }
        CryptDestroyKey(hDuplicateKey);
    } while (!feof(file));

    fclose(Encrypt);
    fclose(file);
    CryptDestroyKey(hSessionKey);
    getchar();
    return 0;
}