#ifndef SOCKET_SERVER_HPP
#include "SocketServer.hpp"
#endif

// Initialize static members
int SocketServer::serverPort = 8000;
sockaddr_in SocketServer::serverAddress;
int SocketServer::serverSocketFd;
std::string SocketServer::serverMode;
std::unordered_map<std::string, int> SocketServer::userAccounts;                                                // 用戶帳戶 <用戶名, 餘額>
std::unordered_map<std::string, std::pair<std::pair<std::string, std::string>, int>> SocketServer::onlineUsers; // 在線用戶 <用戶名, <ip, port>>
std::mutex SocketServer::mutex;

SocketServer::SocketServer(int port, std::string mode)
{
    serverPort = port;
    serverMode = mode;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(serverPort);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    // Create socket
    if ((serverSocketFd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        throw std::runtime_error("Socket creation error");
    }

    // Bind socket
    if (bind(serverSocketFd, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
    {
        throw std::runtime_error("Bind error");
    }

    // Listen for connections
    if (listen(serverSocketFd, 5) < 0)
    {
        throw std::runtime_error("Listen error");
    }

    std::cout << "Server listening on port " << port << "..." << std::endl;
    std::cout << "------------------------" << std::endl;
}

SocketServer::~SocketServer()
{
    close(serverSocketFd);
}

void SocketServer::run()
{
    while (true)
    {
        sockaddr_in clientAddress;
        socklen_t addrLen = sizeof(clientAddress);
        int clientSocketFd = accept(serverSocketFd, (struct sockaddr *)&clientAddress, &addrLen);
        if (clientSocketFd < 0)
        {
            std::cerr << "Accept error" << std::endl;
            continue;
        }
        else
        {
            Client client;
            client.isLogin = false;
            client.ip = inet_ntoa(clientAddress.sin_addr);
            client.socketFd = clientSocketFd;

            pthread_t threadId;
            pthread_create(&threadId, nullptr, &SocketServer::createListener, &client);
        }
    }
}

void *SocketServer::createListener(void *client)
{
    Client client_ = *(Client *)client;

    while (true)
    {
        char recvMessage[2048] = {0};
        recv(client_.socketFd, recvMessage, sizeof(recvMessage), 0);

        std::string request(recvMessage);
        std::string response = processRequest(request, client_);

        if (!response.empty())
        {
            send(client_.socketFd, response.c_str(), response.size(), 0);
            std::cout << "Client IP: " << client_.ip;
            if (client_.isLogin)
            {
                std::cout << ":" << client_.port << std::endl;
            }
            else
            {
                std::cout << std::endl;
            }
            std::cout << "Request: " << request << std::endl;
            std::cout << "Response: " << response << std::endl;
            std::cout << "------------------------" << std::endl;
        }

        if (request == "Exit")
        {
            close(client_.socketFd);
            break;
        }
    }

    return nullptr;
}

std::string SocketServer::getOnlineUserList()
{
    std::string onlineUserList = "online num: " + std::to_string(onlineUsers.size()) + "\r\n";

    for (const auto &user : onlineUsers)
    {
        onlineUserList += user.first + "#" + user.second.first.first + "#" + user.second.first.second + "\r\n";
    }

    return onlineUserList;
};

std::string SocketServer::processRequest(const std::string &request, Client &client)
{
    std::lock_guard<std::mutex> lock(mutex);
    
    int hashCount = 0;

    if (request.find('#') != std::string::npos)
    {
        for (char c : request)
        {
            if (c == '#')
            {
                hashCount++;
            }
        }
    }

    if (request.find("REGISTER#") == 0)
    {
        std::string username = request.substr(9);
        if (userAccounts.find(username) == userAccounts.end())
        {
            userAccounts[username] = 10000;
            return "100 OK\r\n";
        }
        else
        {
            return "210 FAIL\r\n";
        }
    }
    else if (hashCount == 1)
    {
        // 登入邏輯
        std::string username = request.substr(0, request.find('#'));
        std::string portNum = request.substr(request.find('#') + 1);

        if (userAccounts.find(username) != userAccounts.end())
        {
            if (onlineUsers.find(username) != onlineUsers.end())
            {
                return "220 AUTH_FAIL\r\n";
            }
            else
            {
                onlineUsers[username] = std::make_pair(std::make_pair(client.ip, portNum), client.socketFd);
                client.username = username;
                client.port = portNum;
                client.isLogin = true;
            }

            std::string accountBalance = std::to_string(userAccounts[username]); // 獲取用戶餘額
            std::string serverPublicKey = "yourServerPublicKey";                 // 伺服器的公鑰
            std::string onlineUserList = getOnlineUserList();

            return accountBalance + "\r\n" + serverPublicKey + "\r\n" + onlineUserList;
        }
        else
        {
            return "220 AUTH_FAIL\r\n";
        }
    }
    else if (request == "List" && client.isLogin)
    {
        // 返回餘額和上線用戶清單
        std::string accountBalance = std::to_string(userAccounts[client.username]); // 獲取用戶餘額
        std::string serverPublicKey = "yourServerPublicKey";                        // 伺服器的公鑰
        std::string onlineUserList = getOnlineUserList();

        return accountBalance + "\r\n" + serverPublicKey + "\r\n" + onlineUserList;
    }
    else if (hashCount == 2 && client.isLogin)
    {
        // 轉帳邏輯
        std::string payerName = request.substr(0, request.find('#'));
        std::string payeeName = request.substr(request.rfind('#') + 1);
        int money = std::stoi(request.substr(request.find('#') + 1, request.rfind('#') - request.find('#') - 1));

        if (userAccounts.find(payerName) != userAccounts.end() && userAccounts.find(payeeName) != userAccounts.end())
        {
            if (userAccounts[payerName] >= money)
            {
                userAccounts[payerName] -= money;
                userAccounts[payeeName] += money;
                send(onlineUsers[payerName].second, "Transfer OK\r\n", 13, 0);
            }
            else
            {
                send(onlineUsers[payerName].second, "Transfer FAIL\r\n", 15, 0);
            }
        }
        else
        {
            send(onlineUsers[payerName].second, "Transfer FAIL\r\n", 15, 0);
        }

        return "";
    }
    else if (request == "Exit")
    {
        onlineUsers.erase(client.username);
        return "Bye\r\n";
    }

    if (!client.isLogin)
    {
        return "Please login first\r\n";
    }

    return "Invalid request\r\n";
}
