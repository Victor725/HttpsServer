main: main.o CHttp.o
	g++ -o main  main.o CHttp.o -I /usr/local/openssl/include  -L /usr/local/openssl/lib -lssl -lcrypto -lpthread


CHttp:
	g++ -o CHttp CHttp.cpp -I /usr/local/openssl/include  -L /usr/local/openssl/lib

main.o: main.cpp CHttp.h
	g++ -c main.cpp

CHttp.o: CHttp.cpp CHttp.h
	g++ -c CHttp.cpp 


clean:
	rm main.o CHttp.o main CHttp