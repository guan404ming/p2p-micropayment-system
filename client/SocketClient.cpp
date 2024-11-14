#ifndef SOCKET_CLIENT_HPP
#include "SocketClient.hpp"
#endif

std::string SocketClient::serverIp = "127.0.0.1";
int SocketClient::serverPort = 8000;
sockaddr_in SocketClient::serverAddress;
int SocketClient::serverSocketFd;
bool SocketClient::running = true;
bool SocketClient::waiting = false;
ascii::Ascii SocketClient::font = ascii::Ascii(ascii::FontName::sevenstar);

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
}

SocketClient::~SocketClient()
{
    close(serverSocketFd);
}

void *SocketClient::createListener(void *serverPort)
{
    std::string *port = static_cast<std::string *>(serverPort);
    int clientSocketFd = 0;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    // socket connection
    struct sockaddr_in serverInfo, clientInfo;
    socklen_t addrlen = sizeof(clientInfo);

    serverInfo.sin_family = AF_INET;
    serverInfo.sin_addr.s_addr = INADDR_ANY;
    serverInfo.sin_port = htons(std::stoi((char *)port->c_str()));

    if (bind(sockfd, (struct sockaddr *)&serverInfo, sizeof(serverInfo)) < 0)
    {
        std::cerr << "Error: Couldn't bind the server socket! Error: " << strerror(errno) << std::endl;
    }
    listen(sockfd, 5);
    std::cout << "Listening on port " << port->c_str() << std::endl;

    while (true)
    {
        clientSocketFd = accept(sockfd, (struct sockaddr *)&clientInfo, &addrlen);

        // Receive message from client A
        char recvMessage[20] = {0};
        recv(clientSocketFd, recvMessage, sizeof(recvMessage), 0);

        // Send to server
        send(serverSocketFd, recvMessage, sizeof(recvMessage), 0);

        close(clientSocketFd);
    }
}

void SocketClient::run()
{
    while (running)
    {
        std::string option, cmd;
        std::string username, payerUsername, payeeUsername, port, amount;
        std::cout << "\nEnter command: ";
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

            // Create a thread to listen to the port
            pthread_t thread;
            pthread_create(&thread, NULL, &createListener, &port);
        }
        else if (option == "LIST" || option == "c")
        {
            font.print("LIST");
            std::cout << "\n ";
            cmd = "List";
        }
        else if (option == "PAY" || option == "d")
        {
            font.print("PAY");
            std::cout << "\nEnter payer: ";
            getline(std::cin, payerUsername);
            std::cout << "Enter payee: ";
            getline(std::cin, payeeUsername);
            std::cout << "Enter amount: ";
            getline(std::cin, amount);

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

                if (send(receiverSocketFd, cmd.c_str(), cmd.size(), 0) == -1)
                {
                    std::cout << "Send Error" << std::endl;
                }
                cmd = "List";
            }
            else
            {
                std::cout << "Payee not found in the list" << std::endl;
            }

            if (found)
            {
                char buffer[2048] = {0};
                std::cout << buffer << "\n----------------------------------------\n"
                          << std::endl;
                recv(serverSocketFd, buffer, sizeof(buffer), 0);
                std::cout << buffer << "\n----------------------------------------\n"
                          << std::endl;
            }
        }
        else if (option == "EXIT" || option == "e")
        {
            font.print("EXIT");
            std::cout << std::endl;
            cmd = "Exit";
            running = false;
        }
        else
        {
            std::cout << "Invalid command" << std::endl;
            continue;
        }

        if (!cmd.empty())
        {
            char buffer[2048] = {0};

            send(serverSocketFd, cmd.c_str(), cmd.size(), 0);
            int bytesRead = recv(serverSocketFd, buffer, sizeof(buffer), 0);
            std::cout << buffer << std::endl;

            std::cout << "========================================" << std::endl;
        }
    }
}
