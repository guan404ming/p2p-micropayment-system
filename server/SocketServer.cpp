#ifndef SOCKET_SERVER_HPP
#include "SocketServer.hpp"
#endif

// Initialize static members
int SocketServer::serverPort = 8000;
sockaddr_in SocketServer::serverAddress;
int SocketServer::serverSocketFd;
std::string SocketServer::serverMode;
std::unordered_map<std::string, int> SocketServer::userAccounts;                                // 用戶帳戶 <用戶名, 餘額>
std::unordered_map<std::string, std::pair<std::string, std::string>> SocketServer::onlineUsers; // 在線用戶 <用戶名, <ip, port>>

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
            pthread_t threadId;
            pthread_create(&threadId, nullptr, &SocketServer::createListener, &clientSocketFd);
        }
    }
}

void *SocketServer::createListener(void *clientSocketFd)
{
    Client client;
    client.isLogin = false;

    while (true)
    {
        char recvMessage[2048] = {0};
        int clientFd = *(int *)clientSocketFd;
        recv(clientFd, recvMessage, sizeof(recvMessage), 0);

        std::string request(recvMessage);
        std::string response = processRequest(request, client);

        if (!response.empty())
        {
            send(clientFd, response.c_str(), response.size(), 0);
            std::cout << "Req: " << request << std::endl;
            std::cout << "Res: " << response << std::endl;
        }

        if (request == "Exit")
        {
            close(clientFd);
            break;
        }
    }

    return nullptr;
}

std::string SocketServer::processRequest(const std::string &request, Client &client)
{
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
            if (onlineUsers.find(username) == onlineUsers.end())
            {
                onlineUsers[username] = std::make_pair("127.0.0.1", portNum);
                client.username = username;
                client.port = std::stoi(portNum);
                client.isLogin = true;
            }
            else
            {
                return "220 AUTH_FAIL\r\n";
            }

            std::string accountBalance = std::to_string(userAccounts[username]); // 獲取用戶餘額
            std::string serverPublicKey = "YourServerPublicKey";                 // 伺服器的公鑰
            std::string onlineUserList = std::to_string(onlineUsers.size()) + "\r\n";

            for (const auto &user : onlineUsers)
            {
                onlineUserList += user.first + "#" + user.second.first + "#" + user.second.second + "\r\n";
            }

            return accountBalance + "\r\n" + serverPublicKey + "\r\n" + onlineUserList;
        }
        else
        {
            return "220 AUTH_FAIL\r\n";
        }
    }
    else if (request == "List")
    {
        if (client.username.empty())
        {
            return "Please login first\r\n";
        }

        // 返回餘額和上線用戶清單
        std::string accountBalance = std::to_string(userAccounts[client.username]); // 獲取用戶餘額
        std::string serverPublicKey = "YourServerPublicKey";                        // 伺服器的公鑰
        std::string onlineUserList = std::to_string(onlineUsers.size()) + "\r\n";

        for (const auto &user : onlineUsers)
        {
            onlineUserList += user.first + "#" + user.second.first + "#" + user.second.second + "\r\n";
        }

        return accountBalance + "\r\n" + serverPublicKey + "\r\n" + onlineUserList;
    }
    else if (hashCount == 2)
    {
        // 轉帳邏輯
        std::string payerName = request.substr(0, request.find('#'));
        std::string payeeName = request.substr(request.rfind('#') + 1);
        int money = std::stoi(request.substr(request.find('#') + 1, request.rfind('#') - request.find('#') - 1));

        int senderSocketFd = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in receiverAddress;
        receiverAddress.sin_family = AF_INET;
        receiverAddress.sin_port = htons(std::stoi(onlineUsers[payerName].second));
        receiverAddress.sin_addr.s_addr = inet_addr(onlineUsers[payerName].first.c_str());

        if (connect(senderSocketFd, (sockaddr *)&receiverAddress, sizeof(receiverAddress)) == -1)
        {
            std::cout << "Connection Error" << std::endl;
        }

        if (userAccounts.find(payerName) != userAccounts.end() && userAccounts.find(payeeName) != userAccounts.end())
        {
            if (userAccounts[payerName] >= money)
            {
                userAccounts[payerName] -= money;
                userAccounts[payeeName] += money;
                send(senderSocketFd, "Transfer OK\r\n", 13, 0);
            }
            else
            {
                send(senderSocketFd, "Transfer FAIL\r\n", 15, 0);
            }
        }
        else
        {
            send(senderSocketFd, "Transfer FAIL\r\n", 15, 0);
        }

        return "";
    }
    else if (request == "Exit")
    {
        onlineUsers.erase(client.username);
        return "Bye\r\n";
    }

    return "Invalid request\r\n";
}
