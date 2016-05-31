#!/bin/bash

for i in `seq 1 64`;
do
	../01.algorithms/sha256cbc "$1" $i > tmp
   xxd -r -p tmp > 	"$2/$3.$i";  #converte arquivo para binário
done
