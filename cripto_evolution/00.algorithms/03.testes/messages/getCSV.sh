#!/bin/bash

echo "" > file

for d in ./*.txt;
do
		printf "%s,%s\n" "$(cat $d | grep Title: | cut -d ":" -f 2 | xargs )" "$(wc -c $d | awk '{print $1;}')" >> file2.csv


done;
