#include "utils.hpp"

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