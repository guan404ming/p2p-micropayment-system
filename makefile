all: client server thanks

client:
	g++ ./client/*.cpp -o ./client.out -std=c++17

server:
	g++ ./server/*.cpp -o ./server.out -std=c++17

clean:
	rm ./client.out

thanks:
	echo "Make Done!"

.PHONY: all client server clean
.DEFAULT_GOAL: all
