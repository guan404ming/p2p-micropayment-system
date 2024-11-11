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

SocketClient::SocketClient()
{
    if ((serverSocketFd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        throw std::runtime_error("Socket Creation Error");
    }
}

SocketClient::~SocketClient()
{
    close(serverSocketFd);
}

void SocketClient::connectServer(std::string ip, int port)
{
    std::cout << "Setting up server: " << ip << " " << port << std::endl;
    serverIp = ip;
    serverPort = port;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(serverPort);
    serverAddress.sin_addr.s_addr = inet_addr(serverIp.c_str());

    if (connect(serverSocketFd, (sockaddr *)&serverAddress, sizeof(serverAddress)) == -1)
    {
        throw std::runtime_error("Connection Error");
    }
}

void SocketClient::run()
{
    pthread_t serverThread, commandThread;

    pthread_create(&serverThread, nullptr, handleListenServer, nullptr);
    pthread_create(&commandThread, nullptr, handleCommand, nullptr);
    pthread_join(serverThread, nullptr);
}

void *SocketClient::handleListenServer(void *arg)
{
    while (running)
    {
        char buffer[2048] = {0};
        ssize_t bytesRead = recv(serverSocketFd, buffer, 2048, 0);
        std::string rawMessage = std::string(buffer, buffer + bytesRead);
        std::cout << rawMessage << std::endl;
        std::cout << "========================================" << std::endl;
        waiting = false;
    }

    return nullptr;
}

void *SocketClient::handleCommand(void *arg)
{
    while (running)
    {
        std::string option, cmd;
        std::string username, payerUsername, payeeUsername, port, amount;
        std::cout << "\nEnter command: ";
        getline(std::cin, option);

        std::cout << "========================================\n" << std::endl;

        if (option == "REGISTER" or option == "a")
        {
            font.print("REGISTER");
            std::cout << "\nEnter username: ";
            getline(std::cin, username);
            cmd = "REGISTER#" + username;
        }
        else if (option == "LOGIN" or option == "b")
        {
            font.print("LOGIN");
            std::cout << "\nEnter username: ";
            getline(std::cin, username);
            std::cout << "Enter port: ";
            getline(std::cin, port);
            cmd = username + '#' + port;
        }
        else if (option == "LIST" or option == "c")
        {
            font.print("LIST");
            cmd = "List";
        }
        else if (option == "PAY" or option == "d")
        {
            font.print("PAY");
            std::cout << "\nEnter payer: ";
            getline(std::cin, payerUsername);
            std::cout << "Enter payee: ";
            getline(std::cin, payeeUsername);
            std::cout << "Enter amount: ";
            getline(std::cin, amount);

            cmd = payerUsername + '#' + amount + '#' + payeeUsername;
        }
        else if (option == "EXIT" or option == "e")
        {
            font.print("EXIT");
            std::cout << "\n";
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
            send(serverSocketFd, cmd.c_str(), cmd.size(), 0);
            waiting = true;
            while (waiting);
        }
    }

    return nullptr;
}