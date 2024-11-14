all: client thanks

client:
	g++ ./client/*.cpp -o ./client.out -std=c++17

clean:
	rm ./client.out

thanks:
	echo "Make Done!"

.PHONY: all client clean
.DEFAULT_GOAL: all
