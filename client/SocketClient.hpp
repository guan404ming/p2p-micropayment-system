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

class SocketClient { 
  private:
    static std::string serverIp;
    static int serverPort;
    static sockaddr_in serverAddress;
    static int serverSocketFd;
    static bool running;
    static ascii::Ascii font;
    static std::string currentUser;

  public:
    SocketClient(std::string ip, int port);
    ~SocketClient();
    void run();
    static void* createListener(void* ip_port);
};