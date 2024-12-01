#define UTILS_HPP

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <memory>
#include <string>
#include <sstream>
#include <vector>

EVP_PKEY* generateRSAKey(int bits);
std::string getPublicKey(EVP_PKEY* pkey);
std::string getPrivateKey(EVP_PKEY* pkey);
void handleOpenSSLErrors();

std::string encryptMessage(std::string privateKey, const std::string& message);
std::string decryptMessage(std::string publicKey, const std::string& encrypted);