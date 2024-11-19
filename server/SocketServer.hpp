#define SOCKET_SERVER_HPP

#include <iostream>
#include <unordered_map>
#include <vector>
#include <thread>
#include <mutex>
#include <stdexcept>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <sstream>
#include <cstdint>
#include <mutex>

class SocketServer
{
private:
  static int serverPort;
  static sockaddr_in serverAddress;
  static int serverSocketFd;
  static std::string serverMode;
  static std::mutex mutex;

  static std::unordered_map<std::string, int> userAccounts;                                                // Username -> Balance
  static std::unordered_map<std::string, std::pair<std::pair<std::string, std::string>, int>> onlineUsers; // Username -> <IP, Port>

public:
  SocketServer(int port, std::string mode);
  ~SocketServer();

  class Client
  {
  public:
    bool isLogin;
    std::string username;
    std::string port;
    std::string ip;
    int socketFd;
  };

  void run();
  static void *createListener(void *clientSocketFd);
  static std::string processRequest(const std::string &request, Client &client);
  static std::string getOnlineUserList();
};