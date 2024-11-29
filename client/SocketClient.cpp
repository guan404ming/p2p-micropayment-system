#ifndef SOCKET_CLIENT_HPP
#include "SocketClient.hpp"
#endif

std::string SocketClient::serverIp = "127.0.0.1";
int SocketClient::serverPort = 8000;
sockaddr_in SocketClient::serverAddress;
int SocketClient::serverSocketFd;
bool SocketClient::running = true;
ascii::Ascii SocketClient::font = ascii::Ascii(ascii::FontName::sevenstar);
std::string SocketClient::currentUser = "";
std::string SocketClient::publicKey;
std::string SocketClient::privateKey;
std::string SocketClient::serverPublicKey;

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

SocketClient::SocketClient(std::string ip, int port)
{
    serverIp = ip;
    serverPort = port;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(serverPort);
    serverAddress.sin_addr.s_addr = inet_addr(serverIp.c_str());

    // Create a socket
    if ((serverSocketFd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        throw std::runtime_error("Socket Creation Error");
    }

    // Connect to server
    if (connect(serverSocketFd, (sockaddr *)&serverAddress, sizeof(serverAddress)) == -1)
    {
        throw std::runtime_error("Connection Error");
    }

    std::cout << "Connected to server -> " << ip << ":" << port << std::endl;

    // Generate RSA key pair for the client
    RSA* rsa = RSA_generate_key(1024, RSA_F4, nullptr, nullptr);
    if (!rsa) {
        throw std::runtime_error("Error generating RSA key pair.");
    }
    publicKey = getRSAPublicKeyString(rsa);
    privateKey = getRSAPrivateKeyString(rsa);


    char recvMessage[1024] = {0};
    recv(serverSocketFd, recvMessage, sizeof(recvMessage), 0);
    serverPublicKey = recvMessage;

    send(serverSocketFd, publicKey.c_str(), publicKey.length(), 0);

    RSA_free(rsa);
}

SocketClient::~SocketClient()
{
    close(serverSocketFd);
}

void *SocketClient::createListener(void *serverPort)
{
    std::string *port = static_cast<std::string *>(serverPort);
    int clientSocketFd = 0;
    int socketFd = socket(AF_INET, SOCK_STREAM, 0);

    // socket connection
    struct sockaddr_in serverInfo, clientInfo;
    socklen_t addrlen = sizeof(clientInfo);

    serverInfo.sin_family = AF_INET;
    serverInfo.sin_addr.s_addr = INADDR_ANY;
    serverInfo.sin_port = htons(std::stoi((char *)port->c_str()));

    if (bind(socketFd, (struct sockaddr *)&serverInfo, sizeof(serverInfo)) < 0)
    {
        std::cerr << "Error: Couldn't bind the server socket! Error: " << strerror(errno) << std::endl;
    }
    else
    {
        listen(socketFd, 5);
        std::cout << "Listening on port " << port->c_str() << std::endl;

        while (running)
        {
            clientSocketFd = accept(socketFd, (struct sockaddr *)&clientInfo, &addrlen);

            // Receive message from client A
            char recvMessage[20] = {0};
            recv(clientSocketFd, recvMessage, sizeof(recvMessage), 0);

            // Send to server
            send(serverSocketFd, recvMessage, sizeof(recvMessage), 0);
            close(clientSocketFd);
        }
    }

    return nullptr;
}

void logCurrentTime()
{
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now_c), "%Y-%m-%d %H:%M:%S");
    std::cout << "[" << ss.str() << "] ";
}

void SocketClient::run()
{
    auto startTime = std::chrono::system_clock::now();
    logCurrentTime();
    std::cout << "Session started." << std::endl;

    while (running)
    {
        std::string option, cmd;
        std::string username, payerUsername, payeeUsername, port, amount;
        std::cout << "\n";
        logCurrentTime();
        std::cout << "Enter command: ";
        getline(std::cin, option);

        std::cout << "========================================\n"
                  << std::endl;

        if (option == "REGISTER" || option == "a")
        {
            font.print("REGISTER");
            std::cout << "\nEnter username: ";
            getline(std::cin, username);
            cmd = "REGISTER#" + username;
        }
        else if (option == "LOGIN" || option == "b")
        {
            font.print("LOGIN");
            std::cout << "\nEnter username: ";
            getline(std::cin, username);
            std::cout << "Enter port: ";
            getline(std::cin, port);
            cmd = username + '#' + port;

            // Convert port to integer with error handling
            int portNumber;
            try
            {
                if (port.find_first_not_of("0123456789") != std::string::npos)
                {
                    std::cout << "Invalid port" << std::endl;
                    std::cout << "========================================" << std::endl;
                    continue;
                }
                portNumber = std::stoi(port);
            }
            catch (const std::invalid_argument &e)
            {
                std::cout << "Invalid port number" << std::endl;
                continue;
            }
            catch (const std::out_of_range &e)
            {
                std::cout << "Port number out of range" << std::endl;
                continue;
            }

            // Create a thread to listen to the port
            pthread_t thread;
            pthread_create(&thread, NULL, &createListener, &port);
            currentUser = username;
        }
        else if (option == "LIST" || option == "c")
        {
            font.print("LIST");
            std::cout << " \nAmount: ";
            cmd = "List";
        }
        else if (option == "PAY" || option == "d")
        {
            font.print("PAY");
            std::cout << "\nEnter payer: ";
            getline(std::cin, payerUsername);

            if (currentUser == "")
            {
                std::cout << "\nPlease login first!" << std::endl;
                std::cout << "========================================" << std::endl;
                continue;
            }

            if (payerUsername != currentUser)
            {
                std::cout << "\nInvalid payer" << std::endl;
                std::cout << "========================================" << std::endl;
                continue;
            }

            std::cout << "Enter payee: ";
            getline(std::cin, payeeUsername);
            std::cout << "Enter amount: ";
            getline(std::cin, amount);

            if (amount.find_first_not_of("0123456789") != std::string::npos)
            {
                std::cout << "Invalid amount" << std::endl;
                std::cout << "========================================" << std::endl;
                continue;
            }

            // update list
            char list_recv[20000] = {0};

            std::cout << "Auto renew list from tracker before transfer..." << std::endl;
            int listSent = send(serverSocketFd, "List", 4, 0);
            int listRead = recv(serverSocketFd, list_recv, sizeof(list_recv), 0);

            std::string list = list_recv;

            list = list.substr(list.find('\n') + 1);
            list = list.substr(list.find('\n') + 1);
            list = list.substr(list.find('\n') + 1);

            std::string ip, port;
            bool found = false;
            std::string line;
            size_t pos = 0;
            while ((pos = list.find('\n')) != std::string::npos)
            {
                line = list.substr(0, pos);
                list.erase(0, pos + 1);

                std::string username, ipTemp, portTemp;
                size_t firstHash = line.find('#');
                if (firstHash != std::string::npos)
                {
                    username = line.substr(0, firstHash);
                    size_t secondHash = line.find('#', firstHash + 1);
                    if (secondHash != std::string::npos)
                    {
                        ipTemp = line.substr(firstHash + 1, secondHash - firstHash - 1);
                        portTemp = line.substr(secondHash + 1);
                        if (username == payeeUsername)
                        {
                            ip = ipTemp;
                            port = portTemp;
                            found = true;
                            break;
                        }
                    }
                }
            }
            if (found)
            {
                std::cout << "Payee is online at IP: " << ip << ":" << port << std::endl;
                int receiverSocketFd = socket(AF_INET, SOCK_STREAM, 0);
                cmd = payerUsername + '#' + amount + '#' + payeeUsername;
                if (receiverSocketFd == -1)
                {
                    std::cout << "Socket Creation Error" << std::endl;
                }

                sockaddr_in receiverAddress;
                receiverAddress.sin_family = AF_INET;
                receiverAddress.sin_port = htons(std::stoi(port));
                receiverAddress.sin_addr.s_addr = inet_addr(ip.c_str());

                if (connect(receiverSocketFd, (sockaddr *)&receiverAddress, sizeof(receiverAddress)) == -1)
                {
                    std::cout << "Connection Error" << std::endl;
                }

                if (send(receiverSocketFd, cmd.c_str(), cmd.length(), 0) == -1)
                {
                    std::cout << "Send Error" << std::endl;
                }
                else
                {
                    char buffer[2048] = {0};
                    std::cout << "\n----------------------------------------\n"
                              << std::endl;
                    recv(serverSocketFd, buffer, sizeof(buffer), 0);
                    std::cout << buffer << "\n----------------------------------------\n"
                              << std::endl;
                }
                cmd = "List";
            }
            else
            {
                std::cout << "Payee not found in the list" << std::endl;
            }
        }
        else if (option == "EXIT" || option == "e")
        {
            font.print("EXIT");
            std::cout << std::endl;
            cmd = "Exit";
        }
        else
        {
            std::cout << "Invalid command" << std::endl;
            continue;
        }

        if (!cmd.empty())
        {
            char buffer[2048] = {0};

            std::string encryptedMessage = encryptMessage(cmd, serverPublicKey);
            send(serverSocketFd, encryptedMessage.c_str(), encryptedMessage.length(), 0);
            int bytesRead = recv(serverSocketFd, buffer, sizeof(buffer), 0);
            std::cout << buffer << std::endl;
            if (option == "EXIT" || option == "e")
            {
                auto endTime = std::chrono::system_clock::now();
                std::chrono::duration<double> elapsedSeconds = endTime - startTime;
                std::cout << "Session ended. \nDuration: " << elapsedSeconds.count() << " seconds." << std::endl;
                std::cout << "========================================\n";
                running = false;
                break;
            }

            std::cout << "========================================\n";
        }
    }
}
