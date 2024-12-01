#include "utils.hpp"

void handleOpenSSLErrors() {
    std::cerr << "OpenSSL error: " << ERR_error_string(ERR_get_error(), nullptr) << "\n";
}

EVP_PKEY* generateRSAKey(int bits) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr); // Create a context for RSA
    if (!ctx) {
        std::cerr << "Error creating EVP_PKEY_CTX: "
                  << ERR_error_string(ERR_get_error(), nullptr) << "\n";
        return nullptr;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) { // Initialize the context for key generation
        std::cerr << "Error initializing keygen: "
                  << ERR_error_string(ERR_get_error(), nullptr) << "\n";
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) { // Set key length
        std::cerr << "Error setting keygen bits: "
                  << ERR_error_string(ERR_get_error(), nullptr) << "\n";
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) { // Generate the RSA key
        std::cerr << "Error generating RSA key: "
                  << ERR_error_string(ERR_get_error(), nullptr) << "\n";
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx); // Free the context
    return pkey; // Return the generated key
}

// Function to extract the public key as a PEM-encoded string
std::string getPublicKey(EVP_PKEY* pkey) {
    std::ostringstream oss;
    BIO* bio = BIO_new(BIO_s_mem()); // Create a memory BIO
    if (!bio) {
        handleOpenSSLErrors();
        return "";
    }

    if (PEM_write_bio_PUBKEY(bio, pkey) <= 0) { // Write public key to BIO
        handleOpenSSLErrors();
        BIO_free(bio);
        return "";
    }

    char* data = nullptr;
    size_t len = BIO_get_mem_data(bio, &data); // Extract data from BIO
    oss.write(data, len); // Write to string stream

    BIO_free(bio); // Free BIO
    return oss.str();
}

// Function to extract the private key as a PEM-encoded string
std::string getPrivateKey(EVP_PKEY* pkey) {
    std::ostringstream oss;
    BIO* bio = BIO_new(BIO_s_mem()); // Create a memory BIO
    if (!bio) {
        handleOpenSSLErrors();
        return "";
    }

    if (PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) <= 0) { // Write private key
        handleOpenSSLErrors();
        BIO_free(bio);
        return "";
    }

    char* data = nullptr;
    size_t len = BIO_get_mem_data(bio, &data); // Extract data from BIO
    oss.write(data, len); // Write to string stream

    BIO_free(bio); // Free BIO
    return oss.str();
}

// Load a private key from a string
EVP_PKEY* loadPrivateKey(const std::string& privateKeyStr) {
    BIO* bio = BIO_new_mem_buf(privateKeyStr.c_str(), -1);
    if (!bio) {
        handleOpenSSLErrors();
        return nullptr;
    }

    EVP_PKEY* privateKey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!privateKey) {
        handleOpenSSLErrors();
    }
    return privateKey;
}

// Load a public key from a string
EVP_PKEY* loadPublicKey(const std::string& publicKeyStr) {
    BIO* bio = BIO_new_mem_buf(publicKeyStr.c_str(), -1);
    if (!bio) {
        handleOpenSSLErrors();
        return nullptr;
    }

    EVP_PKEY* publicKey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!publicKey) {
        handleOpenSSLErrors();
    }
    return publicKey;
}

// Encrypt with private key
std::string encryptMessage(std::string publicKey_, const std::string& message) {
    EVP_PKEY* publicKey = loadPublicKey(publicKey_);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(publicKey, nullptr);
    if (!ctx) {
        handleOpenSSLErrors();
        return "";
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        handleOpenSSLErrors();
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    size_t outLen = 0;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outLen, reinterpret_cast<const unsigned char*>(message.c_str()), message.size()) <= 0) {
        handleOpenSSLErrors();
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    std::vector<unsigned char> encrypted(outLen);
    if (EVP_PKEY_encrypt(ctx, encrypted.data(), &outLen, reinterpret_cast<const unsigned char*>(message.c_str()), message.size()) <= 0) {
        handleOpenSSLErrors();
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    encrypted.resize(outLen);
    EVP_PKEY_CTX_free(ctx);
    return std::string(encrypted.begin(), encrypted.end());
}

// Decrypt with public key
std::string decryptMessage(std::string privateKey_, const std::string& encrypted) {
    EVP_PKEY* privateKey = loadPrivateKey(privateKey_);
    if (!privateKey) {
        handleOpenSSLErrors();
        return "";
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privateKey, nullptr);
    if (!ctx) {
        handleOpenSSLErrors();
        return "";
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        handleOpenSSLErrors();
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    size_t outLen = 0;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outLen, reinterpret_cast<const unsigned char*>(encrypted.data()), encrypted.size()) <= 0) {
        handleOpenSSLErrors();
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    std::vector<unsigned char> decrypted(outLen);
    if (EVP_PKEY_decrypt(ctx, decrypted.data(), &outLen, reinterpret_cast<const unsigned char*>(encrypted.data()), encrypted.size()) <= 0) {
        handleOpenSSLErrors();
        EVP_PKEY_CTX_free(ctx);
        return "";
    }

    decrypted.resize(outLen);
    EVP_PKEY_CTX_free(ctx);
    return std::string(decrypted.begin(), decrypted.end());
}
