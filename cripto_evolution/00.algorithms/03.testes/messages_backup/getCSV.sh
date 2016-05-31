#!/bin/bash

echo "" > file

for d in ./;
do
		printf "%s,%s" "$(cat $d | grep Title:)" "$(wc -c $d | awk '{print$1;}')" >> file


done;
