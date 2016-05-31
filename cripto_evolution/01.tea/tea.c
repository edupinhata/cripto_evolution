
//  Copyright (C) 2013 ebftpd team
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
//  GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.    If not, see <http://www.gnu.org/licenses/>.
//

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include "xtea.h"

#define XTEA_DELTA          0x9E3779B9
#define XTEA_NUM_ROUNDS     32

void XTeaEncrypt(const unsigned char src[XTEA_BLOCK_SIZE],
                 unsigned char dst[XTEA_BLOCK_SIZE],
                 const unsigned char ckey[XTEA_KEY_SIZE],
				 int num_rounds)
{
    const uint32_t* s = (const uint32_t*)src;
    uint32_t s0 = s[0];
    uint32_t s1 = s[1];
    uint32_t sum = 0;
    uint32_t* key = (uint32_t*)ckey;
    uint32_t* d = (uint32_t*)dst;
	uint32_t k0=key[0], k1=key[1], k2=key[2], k3=key[3];
    unsigned int i;
    for (i = 0; i < num_rounds; i++) {
       sum += XTEA_DELTA;
	   s0 += ((s1<<4) + k0) ^ (s1 + sum) ^ ((s1>>5) + k1);
	   s1 += ((s0<<4) + k2) ^ (s0 + sum) ^ ((s0>>5) + k3);
		   
    }

    d[0] = s0;
    d[1] = s1;
}

ssize_t XTeaEncryptECB(const unsigned char* src, size_t srcLen,
                       unsigned char* dst, size_t dstSize,
                       const unsigned char* key,
					   int num_rounds)
{
    ssize_t remaining = srcLen;
    ssize_t dstLen = srcLen;

    if (dstSize < srcLen) { return -1; }

    while (remaining >= XTEA_BLOCK_SIZE) {
        XTeaEncrypt(src, dst, key, num_rounds);
        src += XTEA_BLOCK_SIZE;
        remaining -= XTEA_BLOCK_SIZE;
        dst += XTEA_BLOCK_SIZE;
    }

    unsigned char last[XTEA_BLOCK_SIZE];
    unsigned int padding;
    if (remaining > 0) {
        padding = XTEA_BLOCK_SIZE - remaining;
        memcpy(last, src, remaining);
    }
    else if (dstSize >= srcLen + XTEA_BLOCK_SIZE) {
        padding = XTEA_BLOCK_SIZE;
    }
    else {
	//printf("Saiu no padding encrypt\n");
        return -1;
    }

    unsigned char pad = '0' + padding;
    //printf("Pasdding: %c\n", pad);
    dstLen += padding;
    memset(last + remaining, pad, padding);
    XTeaEncrypt(last, dst, key, num_rounds);

    return dstLen;
}

ssize_t XTeaEncryptCBC(const unsigned char* src, size_t srcLen,
                       unsigned char* dst, size_t dstSize,
                       const unsigned char ivec[XTEA_BLOCK_SIZE],
                       const unsigned char key[XTEA_KEY_SIZE],
					   int num_rounds)
{
    ssize_t remaining = srcLen;
    ssize_t dstLen = srcLen;

    if (dstSize < srcLen) { return -1; }

    unsigned char block[XTEA_BLOCK_SIZE];
    unsigned char iv[XTEA_BLOCK_SIZE];
    memcpy(iv, ivec, XTEA_BLOCK_SIZE);
    while (remaining >= XTEA_BLOCK_SIZE) {

        memcpy(block, src, XTEA_BLOCK_SIZE);
        unsigned int i;
        for (i = 0; i < XTEA_BLOCK_SIZE; ++i) {
            block[i] = (unsigned char)block[i] ^ iv[i];
        }

        XTeaEncrypt(block, dst, key, num_rounds);
        memcpy(iv, dst, XTEA_BLOCK_SIZE);
        src += XTEA_BLOCK_SIZE;
        remaining -= XTEA_BLOCK_SIZE;
        dst += XTEA_BLOCK_SIZE;
    }

    unsigned int padding;
    if (remaining > 0) {
        padding = XTEA_BLOCK_SIZE - remaining;
        memcpy(block, src, remaining);
    }
    else if (dstSize >= srcLen + XTEA_BLOCK_SIZE) {
        padding = XTEA_BLOCK_SIZE;
    }
    else {
        return -1;
    }

    unsigned char pad = '0' + padding;
    memset(block + remaining, pad, padding);
    dstLen += padding;
    unsigned int i;
    for (i = 0; i < XTEA_BLOCK_SIZE; ++i) {
        block[i] = (unsigned char)block[i] ^ iv[i];
    }
    XTeaEncrypt(block, dst, key, num_rounds);

    return dstLen;
}

void XTeaDecrypt(const unsigned char src[XTEA_BLOCK_SIZE],
                 unsigned char dst[XTEA_BLOCK_SIZE],
                 const unsigned char ckey[XTEA_KEY_SIZE],
				 int num_rounds)
{
    const uint32_t* s = (const uint32_t*)src;
    uint32_t s0 = s[0];
    uint32_t s1 = s[1];
    uint32_t sum = XTEA_DELTA * num_rounds;
    uint32_t* key = (uint32_t*)ckey;
    uint32_t k0=key[0], k1=key[1], k2=key[2], k3=key[3];
	uint32_t* d = (uint32_t*)dst;

    unsigned int i;
    for (i = 0; i < num_rounds; i++) {
		s1 -= ((s0<<4) + k2) ^ (s0 + sum) ^ ((s0>>5) + k3);
		s0 -= ((s1<<4) + k0) ^ (s1 + sum) ^ ((s1>>5) + k1);
    	sum -= XTEA_DELTA;
			
	}
    
    d[0] = s0;
    d[1] = s1;
}

ssize_t XTeaDecryptECB(const unsigned char* src, size_t srcLen,
                       unsigned char* dst, size_t dstSize,
                       const unsigned char* key,
					   int num_rounds)
{
    ssize_t remaining = srcLen;
    ssize_t dstLen = srcLen;
    //printf("Dst Size: %lu\nsrcLen: %lu\nsrcLen mod xtea_block_size: %lu", 
		    //dstLen, srcLen, srcLen%XTEA_BLOCK_SIZE);


    if(dstSize < srcLen){
		//printf("DstSizeTrue1: %lu\n", dstSize);
		//printf("SrcLenTrue1: %lu\n", srcLen);
	    printf("True 1.\n");

    }
    //if(srcLen%XTEA_BLOCK_SIZE != 0)
	    //printf("True 2");

    if (dstSize < srcLen || srcLen % XTEA_BLOCK_SIZE != 0) { 
	    //printf("Motor falhou\n"); 
		//printf("srcLen mod XTEA: %lu\n", srcLen%XTEA_BLOCK_SIZE);
		//printf("dstSize: %zd\n", dstSize);
		//printf("srcLen: %zd\n", srcLen);
	    return -1; }


    //printf("Chegou a venus");

    while (remaining > 0) {
        XTeaDecrypt(src, dst, key, num_rounds);
        src += XTEA_BLOCK_SIZE;
        remaining -= XTEA_BLOCK_SIZE;
        dst += XTEA_BLOCK_SIZE;
    }

   //printf("chegou a mercurio"); 
   //printf("Message in DecryptECB: %s\n", dst-XTEA_BLOCK_SIZE);
    //printf("TEsting it: %d\n", *(dst-1));
//printf("TEsting it: %d'n", '0');
    //printf("TEsting it: %d\n", *(dst-1) - '0');
//printf("TEsting it: %d", *(dst));

    int padding = *(dst - 1) - '0';
    if (padding < 1 || (unsigned int)padding > XTEA_BLOCK_SIZE) { 
	    //printf("erro aqui"); 
	    return -1; }
	//printf("Some debug:\n");
	//printf("dstLen: %zd\n", dstLen);
	//printf("padding: %d\n", padding);


    return dstLen - padding;
}

ssize_t XTeaDecryptCBC(const unsigned char* src, size_t srcLen,
                       unsigned char* dst, size_t dstSize,
                       const unsigned char ivec[XTEA_BLOCK_SIZE],
                       const unsigned char key[XTEA_KEY_SIZE],
					   int num_rounds)
{
    ssize_t remaining = srcLen;
    ssize_t dstLen = srcLen;

    if (dstSize < srcLen || srcLen % XTEA_BLOCK_SIZE != 0) { return -1; }

    unsigned char temp[XTEA_BLOCK_SIZE];
    unsigned char iv[XTEA_BLOCK_SIZE];
    memcpy(iv, ivec, XTEA_BLOCK_SIZE);
    while (remaining > 0) {

        memcpy(temp, src, XTEA_BLOCK_SIZE);
        XTeaDecrypt(src, dst, key, num_rounds);

        unsigned int i;
        for (i = 0; i < XTEA_BLOCK_SIZE; ++i) {
            dst[i] = (unsigned char)dst[i] ^ iv[i];
        }

        src += XTEA_BLOCK_SIZE;
        remaining -= XTEA_BLOCK_SIZE;
        dst += XTEA_BLOCK_SIZE;
        memcpy(iv, temp, XTEA_BLOCK_SIZE);
    }

    int padding = *(dst - 1) - '0';
    if (padding < 1 || (unsigned int)padding > XTEA_BLOCK_SIZE) { return -1; }

    return dstLen - padding;
}

int XTeaGenerateIVec(unsigned char ivec[XTEA_BLOCK_SIZE])
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) { return -1; }

    ssize_t ret = read(fd, ivec, XTEA_BLOCK_SIZE);
    close(fd);

    return ret == XTEA_BLOCK_SIZE ? 0 : -1;
}


int main(int argc, char ** argv){

	unsigned char * key = (unsigned char*)argv[2];

    FILE *fp;
	long lSize;
	unsigned char *buffer;
	int num_rounds = atoi(argv[3]);


	fp = fopen ( argv[1] , "rb" );
	if( !fp ) perror(argv[1]),exit(1);

	fseek( fp , 0L , SEEK_END);
	lSize = ftell( fp );
	rewind( fp );
	
	/* allocate memory for entire content */
	buffer = calloc( 1, lSize+1 );
	if( !buffer ) fclose(fp),fputs("memory alloc fails",stderr),exit(1);

	/* copy the file into the buffer */
	if( 1!=fread( buffer, lSize, 1 , fp) )
		fclose(fp),free(buffer),fputs("entire read fails",stderr),exit(1);
											        
	unsigned char * enc_msg = calloc(1, lSize+1+XTEA_BLOCK_SIZE);

	int dstLen = (int)XTeaEncryptECB(buffer, lSize,
                       enc_msg, lSize+XTEA_BLOCK_SIZE,
                       key, num_rounds);

	free(buffer);

	/*printing result in hexadecimal */
	for(int j=0; j<dstLen; j++)
		printf("%02x", enc_msg[j]);

		
/*  Decrypt part. I made this part to 
 *  test if the algorithm is working fine.
 *
	unsigned char * final_result = calloc(1, dstLen+1);
	

	int message_size = (int)XTeaDecryptECB(enc_msg, dstLen,
                       final_result, dstLen,
                       key, num_rounds);


	char * final_message = calloc(1, message_size+1);
	memcpy(final_message, final_result, message_size);
	//printf("Size of the message: %d\n", message_size);
	//printf("Decrypted: %s\n", final_result);
	printf("%s", final_message);
*/

	return 0;
}
