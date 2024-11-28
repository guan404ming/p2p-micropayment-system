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
std::string SocketServer::publicKey;
std::string SocketServer::privateKey;


std::string getRSAPublicKeyString(RSA *rsa)
{
    BIO *bioPublic = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bioPublic, rsa);
    char buffer[1024] = {0};
    BIO_read(bioPublic, buffer, 1024);
    BIO_free(bioPublic);
    return std::string(buffer);
}

std::string getRSAPrivateKeyString(RSA *rsa)
{
    BIO *bioPublic = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bioPublic, rsa, nullptr, nullptr, 0, nullptr, nullptr);
    char buffer[1024] = {0};
    BIO_read(bioPublic, buffer, 1024);
    BIO_free(bioPublic);
    return std::string(buffer);
}

RSA *getRSAPublicKey(const std::string &keyString)
{
    BIO *bioRSA = BIO_new_mem_buf(keyString.c_str(), strlen(keyString.c_str()));
    RSA *rsa = PEM_read_bio_RSAPublicKey(bioRSA, nullptr, nullptr, nullptr);
    if (!rsa)
    {
        std::cout << "Error: RSA public key" << std::endl;
        return nullptr;
    }
    BIO_free(bioRSA);
    return rsa;
}

RSA *getRSAPrivateKey(const std::string &keyString)
{
    BIO *bioRSA = BIO_new_mem_buf(keyString.c_str(), strlen(keyString.c_str()));
    RSA *rsa = PEM_read_bio_RSAPrivateKey(bioRSA, nullptr, nullptr, nullptr);
    if (!rsa)
    {
        std::cout << "Error: RSA private key" << std::endl;
        return nullptr;
    }
    BIO_free(bioRSA);
    return rsa;
}

std::string encryptMessage(const std::string &plaintext, const std::string &publicKey)
{
    RSA *rsa = getRSAPublicKey(publicKey);
    // Convert the plaintext to unsigned char buffer
    const unsigned char *inputBuffer = reinterpret_cast<const unsigned char *>(plaintext.c_str());
    int inputLength = static_cast<int>(plaintext.length());

    // Determine the size of the output buffer
    int outputLength = RSA_size(rsa);

    // Allocate a C-style buffer
    unsigned char *outputBuffer = new unsigned char[outputLength]{0};

    // Perform the encryption
    int result = RSA_public_encrypt(inputLength, inputBuffer, outputBuffer, rsa, RSA_PKCS1_PADDING);

    if (result == -1)
    {
        // Handle encryption error
        std::cout << "Error: Encryption Failed." << std::endl;
        delete[] outputBuffer;
        RSA_free(rsa);
        return "";
    }

    // Convert the encrypted data to a string for storage/transmission
    std::string encryptedMessage(outputBuffer, outputBuffer + result);

    // Clean up the allocated buffer
    delete[] outputBuffer;
    RSA_free(rsa);

    return encryptedMessage;
}

std::string decryptMessage(const std::string &encryptedMessage, const std::string &privateKey)
{
    RSA *rsa = getRSAPrivateKey(privateKey);

    // Convert the encrypted data to unsigned char buffer
    const unsigned char *inputBuffer = reinterpret_cast<const unsigned char *>(encryptedMessage.c_str());
    int inputLength = static_cast<int>(encryptedMessage.length());

    // Determine the size of the output buffer
    int outputLength = RSA_size(rsa);

    // Allocate a C-style buffer
    unsigned char *outputBuffer = new unsigned char[outputLength]{0};

    // Perform the decryption
    int result = RSA_private_decrypt(inputLength, inputBuffer, outputBuffer, rsa, RSA_PKCS1_PADDING);

    if (result == -1)
    {
        // Handle decryption error
        std::cout << "Error: Decryption Failed." << std::endl;
        delete[] outputBuffer;
        return "";
    }

    // Convert the decrypted data to a string
    std::string decryptedMessage(outputBuffer, outputBuffer + result);

    // Clean up the allocated buffer
    delete[] outputBuffer;
    RSA_free(rsa);

    return decryptedMessage;
}

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

    // Generate RSA key pair for the client
    RSA* rsa = RSA_generate_key(1024, RSA_F4, nullptr, nullptr);
    if (!rsa) {
        throw std::runtime_error("Error generating RSA key pair.");
    }
    publicKey = getRSAPublicKeyString(rsa);
    privateKey = getRSAPrivateKeyString(rsa);
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

            send(clientSocketFd, publicKey.c_str(), publicKey.size(), 0);

            char recvMessage[1024] = {0};
            recv(clientSocketFd, recvMessage, sizeof(recvMessage), 0);
            client.publicKey = recvMessage;

            std::cout << "Client key: " << client.publicKey << std::endl;

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
        char recvMessage[20000] = {0};
        recv(client_.socketFd, recvMessage, sizeof(recvMessage), 0);

        std::string request(recvMessage);
        request = decryptMessage(request, privateKey);
        std::cout << "Decrypted message: " << request << std::endl;
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
