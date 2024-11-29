#ifndef SOCKET_SERVER_HPP
#include "SocketServer.hpp"
#endif

int main(int argc, char const *argv[])
{
    if (argc < 3)
    {
        std::cout << "Usage: ./<filename> <port> [-options]" << std::endl;
        return -1;
    }

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, nullptr);
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SocketServer server(std::stoi(std::string(argv[1])), std::string(argv[2]));
    server.run();
    return 0;
}