#!/bin/bash


for i in `seq 1 32`;
do
	../01.algorithms/xtea "$1" "$2" $i > tmp
	xxd -r -p tmp > "$3/$4.$i"; #converts file to binary
done	
