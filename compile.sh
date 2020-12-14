#!/bin/bash
for i in `ls test/*.cpp`
do
	FILENAME=$(basename $i .cpp)
	echo $FILENAME
	rm ./out/$FILENAME.o
	g++ -o ./out/$FILENAME.o test/$FILENAME.cpp src/*.cpp -lpcap -pthread -Wall -O2 -Wl,--wrap,socket -Wl,--wrap,bind -Wl,--wrap,listen -Wl,--wrap,connect -Wl,--wrap,accept -Wl,--wrap,read -Wl,--wrap,write -Wl,--wrap,close -Wl,--wrap,getaddrinfo
done
