#!/bin/bash
COUNT=1
for f in ../03.testes/messages/*
do

	#creating message and password
	#message=$(eval "aesrng 1024 |uuencode - > test");
	password="testing";

	#savinf message into a message folder
	#message_dir="../03.testes/01.messages";
	#cp test "$message_dir"; #copy file to message dir
	#mv "$message_dir/test" "$message_dir/message.$COUNT"; #change message name


	#creating variables do define which 
	#algorithms will be used
	b_tea=true
	b_xtea=true
	b_md4=false
	b_md4ecb=true
	b_md4cbc=true
	b_md5=false
	b_md5ecb=true
	b_md5cbc=true
	b_sha256=false
	b_sha256ecb=true
	b_sha256cbc=true


	#creating dir paths	
	tea_dir="../03.testes/tea_$COUNT";
	xtea_dir="../03.testes/xtea_$COUNT";
	md4_dir="../03.testes/md4_$COUNT";
	md4cbc_dir="../03.testes/md4cbc_$COUNT";
	md4ecb_dir="../03.testes/md4ecb_$COUNT";
	md5_dir="../03.testes/md5_$COUNT";
	md5cbc_dir="../03.testes/md5cbc_$COUNT";
	md5ecb_dir="../03.testes/md5ecb_$COUNT";
	sha256_dir="../03.testes/sha256_$COUNT";
	sha256cbc_dir="../03.testes/sha256cbc_$COUNT";
	sha256ecb_dir="../03.testes/sha256ecb_$COUNT";

	#creating file names
	tea_file="tea_$COUNT";
	xtea_file="xtea_$COUNT";
	md4_file="md4_$COUNT";
	md4cbc_file="md4cbc_$COUNT";
	md4ecb_file="md4ecb_$COUNT";
	md5_file="md5_$COUNT";
	md5cbc_file="md5cbc_$COUNT";
	md5ecb_file="md5ecb_$COUNT";
	sha256_file="sha256_$COUNT";
	sha256cbc_file="sha256cbc_$COUNT";
	sha256ecb_file="sha256ecb_$COUNT";

	#creating directories
	#mkdir $tea_dir;
	#mkdir $xtea_dir;
	#mkdir $md4_dir;
	#mkdir $md4cbc_dir;
	#mkdir $md4ecb_dir;
	#mkdir $md5_dir;
	#mkdir $md5cbc_dir;
	#mkdir $md5ecb_dir;
	#mkdir $sha256_dir;
	#mkdir $sha256cbc_dir;
	#mkdir $sha256ecb_dir;

	#running the algorithms	
	if [ "$b_tea" = true ]; then
		mkdir $tea_dir;
		./01.generators/teaGen.sh $f $password $tea_dir $tea_file;
	fi
	if [ "$b_xtea" = true ]; then
		mkdir $xtea_dir;
		./01.generators/xteaGen.sh $f $password $xtea_dir $xtea_file;
	fi
	if [ "$b_md4" = true ]; then
		mkdir $md4_dir;
		./01.generators/md4Gen.sh $f $md4_dir $md4_file;
	fi
	if [ "$b_md4cbc" = true ]; then 
		mkdir $md4cbc_dir;
		./01.generators/md4cbcGen.sh $f $md4cbc_dir $md4cbc_file;
	fi
	if [ "$b_md4ecb" = true ]; then
		mkdir $md4ecb_dir;
		./01.generators/md4ecbGen.sh $f $md4ecb_dir $md4ecb_file;
	fi
	if [ "$b_md5" = true ]; then
		mkdir $md5_dir;
		./01.generators/md5Gen.sh $f $md5_dir $md5_file;
	fi
	if [ "$b_md5cbc" = true ]; then
		mkdir $md5cbc_dir;
		./01.generators/md5cbcGen.sh $f $md5cbc_dir $md5cbc_file;
	fi
	if [ "$b_md5ecb" = true ]; then
		mkdir $md5ecb_dir;
		./01.generators/md5ecbGen.sh $f $md5ecb_dir $md5ecb_file;
	fi
	if [ "$b_sha256" = true ]; then
		mkdir $sha256_dir;
		./01.generators/sha256Gen.sh $f $sha256_dir $sha256_file;
	fi
	if [ "$b_sha256cbc" = true ]; then
		mkdir $sha256cbc_dir;
		./01.generators/sha256cbcGen.sh $f $sha256cbc_dir $sha256cbc_file;
	fi
	if [ "$b_sha256ecb" = true ]; then
		mkdir $sha256ecb_dir;
		./01.generators/sha256ecbGen.sh $f $sha256ecb_dir $sha256ecb_file;
	fi

	COUNT=$(($COUNT+1))
done

