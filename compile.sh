#!/bin/bash
for i in `ls test/*.cpp`
do
	FILENAME=$(basename $i .cpp)
	echo $FILENAME
	rm ./out/$FILENAME.o
	g++ -o ./out/$FILENAME.o test/$FILENAME.cpp src/*.cpp -lpcap -Wall -O2 
done
