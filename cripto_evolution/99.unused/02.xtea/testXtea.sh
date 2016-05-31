#!/bin/bash

aesrng $1 |uuencode utf8  > test

./xtea test "pswd" 32 > test2

var1="$(openssl md5 < test)"
var2="$(openssl md5 < test2)"


if [ $var1 == $var2 ];
then
	echo "Equal"
else 
	echo "Different"
fi
