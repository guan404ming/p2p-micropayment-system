#define SOCKET_CLIENT_HPP

#include <iostream>
#include <stdio.h>  
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <map>
#include <cerrno>
#include <cstring>
#include <chrono>
#include <sstream>
#include <iomanip>
#include "../lib/Ascii.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

class SocketClient { 
  private:
    static std::string serverIp;
    static int serverPort;
    static sockaddr_in serverAddress;
    static int serverSocketFd;
    static bool running;
    static ascii::Ascii font;
    static std::string currentUser;
    
    static std::string serverPublicKey;
    static std::string publicKey;
    static std::string privateKey;
    static std::string peerPublicKey;

  public:
    SocketClient(std::string ip, int port);
    ~SocketClient();
    void run();
    static void* createListener(void* ip_port);
};