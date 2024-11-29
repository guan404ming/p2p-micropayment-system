#define UTILS_HPP

#include <iostream>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

EVP_PKEY* generateRSAKey(int bits);