#!/bin/bash

echo "" > ../03.testes/file; 
#for d in ../03.testes/$1_*;
for d in ../03.testes/*_*;	
do
	echo $d
	cd $d; 
	for f in ./*; 
	do  
		#echo $f >> ../file;  
		#ent $f | grep Entropy >> ../file ;
		##printf "%s;%s;%s;%s\n" "$(echo $f | grep -Eo '[a-zA-Z]+[0-9]*')" "$( echo $f | grep -Eo '[0-9]+\.[0-9]+' | grep -Eo '[0-9]+' | head -1)"  "$( echo $f | grep -Eo '\.[0-9]+' | grep -Eo '[0-9]+')" "$(ent $f | grep Entropy | grep -Eo '[0-9]+.[0-9]+')" >> ../file
		printf "%s,%s,%s,%s\n" "$(echo $f | grep -Eo '[a-zA-Z]+[0-9]*[a-zA-Z]*')" "$(echo $f | grep -Eo '[0-9]+\.[0-9]+' | grep -Eo '[0-9]+' | head -1)"  "$(echo $f | grep -Eo '\.[0-9]+' | grep -Eo '[0-9]+')" "$(ent -t $f | grep 1)" >> ../file	
	done; 
	cd ../; 
done; 
