all: client server thanks

client:
	g++ ./client/*.cpp -o ./client.out -std=c++17 -std=c++17 -L/opt/homebrew/opt/openssl/lib -I/opt/homebrew/opt/openssl/include -lssl -lcrypto

server:
	g++ ./server/*.cpp -o ./server.out -std=c++17

clean:
	rm ./client.out

thanks:
	echo "Make Done!"

.PHONY: all client server clean
.DEFAULT_GOAL: all
