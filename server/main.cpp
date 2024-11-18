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

    SocketServer server(std::stoi(std::string(argv[1])), std::string(argv[2]));
    server.run();
    return 0;
}