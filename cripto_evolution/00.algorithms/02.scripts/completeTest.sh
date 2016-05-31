#!/bin/bash


for COUNT in `SEQ 1 100`
do
	#creating message and password
	message=$(eval "aesrng 1024 |uuencode - > test");
	password="testing";

	#savinf message into a message folder
	message_dir="../03.testes/01.messages";
	cp test "$message_dir"; #copy file to message dir
	mv "$message_dir/test" "$message_dir/message.$COUNT"; #change message name

	#creating dir paths	
	tea_dir="../03.testes/tea_$COUNT";
	xtea_dir="../03.testes/xtea_$COUNT";
	md4_dir="../03.testes/md4_$COUNT";
	md5_dir="../03.testes/md5_$COUNT";
	sha256_dir="../03.testes/sha256_$COUNT";
	
	#creating file names
	tea_file="tea_$COUNT";
	xtea_file="xtea_$COUNT";
	md4_file="md4_$COUNT";
	md5_file="md5_$COUNT";
	sha256_file="sha256_$COUNT";
	
	#creating directories
	mkdir $tea_dir;
	mkdir $xtea_dir;
	mkdir $md4_dir;
	mkdir $md5_dir;
	mkdir $sha256_dir;

	#running the algorithms	
	./01.generators/teaGen.sh test $password $tea_dir $tea_file;
	./01.generators/xteaGen.sh test $password $xtea_dir $xtea_file;
	./01.generators/md4Gen.sh test $md4_dir $md4_file;
	./01.generators/md5Gen.sh test $md5_dir $md5_file;
	./01.generators/sha256Gen.sh test $sha256_dir $sha256_file;
done
