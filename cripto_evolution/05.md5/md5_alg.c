/*
 * This is an OpenSSL-compatible implementation of the RSA Data Security, Inc.
 * MD5 Message-Digest Algorithm (RFC 1321).
 *
 * Homepage:
 * http://openwall.info/wiki/people/solar/software/public-domain-source-code/md5
 *
 * Author:
 * Alexander Peslyak, better known as Solar Designer <solar at openwall.com>
 *
 * This software was written by Alexander Peslyak in 2001.  No copyright is
 * claimed, and the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the
 * public domain is deemed null and void, then the software is
 * Copyright (c) 2001 Alexander Peslyak and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * (This is a heavily cut-down "BSD license".)
 *
 * This differs from Colin Plumb's older public domain implementation in that
 * no exactly 32-bit integer data type is required (any 32-bit or wider
 * unsigned integer data type will do), there's no compile-time endianness
 * configuration, and the function prototypes match OpenSSL's.  No code from
 * Colin Plumb's implementation has been reused; this comment merely compares
 * the properties of the two independent implementations.
 *
 * The primary goals of this implementation are portability and ease of use.
 * It is meant to be fast, but not as fast as possible.  Some known
 * optimizations are not included to reduce source code size and avoid
 * compile-time configuration.
 */
 
#ifndef HAVE_OPENSSL
 
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
 
#include "md5.h"
 
/*
 * The basic MD5 functions.
 *
 * F and G are optimized compared to their RFC 1321 definitions for
 * architectures that lack an AND-NOT instruction, just like in Colin Plumb's
 * implementation.
 */
#define F(x, y, z)			((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)			((y) ^ ((z) & ((x) ^ (y))))
#define H(x, y, z)			((x) ^ (y) ^ (z))
#define I(x, y, z)			((y) ^ ((x) | ~(z)))
 
/*
 * The MD5 transformation for all four rounds.
 */
#define STEP(f, a, b, c, d, x, t, s) \
	(a) += f((b), (c), (d)) + (x) + (t); \
	(a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s)))); \
	(a) += (b);
 
/*
 * SET reads 4 input bytes in little-endian byte order and stores them
 * in a properly aligned word in host byte order.
 *
 * The check for little-endian architectures that tolerate unaligned
 * memory accesses is just an optimization.  Nothing will break if it
 * doesn't work.
 */
#if defined(__i386__) || defined(__x86_64__) || defined(__vax__)
#define SET(n) \
	(*(MD5_u32plus *)&ptr[(n) * 4])
#define GET(n) \
	SET(n)
#else
#define SET(n)		   \
	(ctx->block[(n)] = \
	(MD5_u32plus)ptr[(n) * 4] | \
	((MD5_u32plus)ptr[(n) * 4 + 1] << 8) | \
	((MD5_u32plus)ptr[(n) * 4 + 2] << 16) | \
	((MD5_u32plus)ptr[(n) * 4 + 3] << 24))
#define GET(n)					\
	(ctx->block[(n)])
#endif
 
 //&ptr[x] é igual a (ptr + x)
 //&ptr[(n) * 4], ptr aponta para o início de um vetor, o código ao lado pega o endereço do elemento n*4 a partir de ptr
 //(*(MD5_u32plus ) vai receber o endereço acessado por &ptr((n) * 4)
 //o * depois de MD5.. indica que MD5... está sendo transformado (typecasting) em um ponteiro e não no tipo em si
 
 
/*
 * This processes one or more 64-byte data blocks, but does NOT update
 * the bit counters.  There are no alignment requirements.
 */
static void *body(MD5_CTX *ctx, void *data, unsigned long size, int rounds)
{
	unsigned char *ptr;
	MD5_u32plus a, b, c, d;
	MD5_u32plus saved_a, saved_b, saved_c, saved_d;
 
	ptr = data;
 
	a = ctx->a;
	b = ctx->b;
	c = ctx->c;
	d = ctx->d;
 
	do {
		saved_a = a;
		saved_b = b;
		saved_c = c;
		saved_d = d;
 
/* Round 1 */
	if(rounds>0)
		STEP(F, a, b, c, d, SET(0), 0xd76aa478, 7)
	if(rounds>1)
		STEP(F, d, a, b, c, SET(1), 0xe8c7b756, 12)
	if(rounds>2)
		STEP(F, c, d, a, b, SET(2), 0x242070db, 17)
	if(rounds>3)
		STEP(F, b, c, d, a, SET(3), 0xc1bdceee, 22)
	if(rounds>4)
		STEP(F, a, b, c, d, SET(4), 0xf57c0faf, 7)
	if(rounds>5)
		STEP(F, d, a, b, c, SET(5), 0x4787c62a, 12)
	if(rounds>6)
		STEP(F, c, d, a, b, SET(6), 0xa8304613, 17)
	if(rounds>7)
		STEP(F, b, c, d, a, SET(7), 0xfd469501, 22)
	if(rounds>8)
		STEP(F, a, b, c, d, SET(8), 0x698098d8, 7)
	if(rounds>9)
		STEP(F, d, a, b, c, SET(9), 0x8b44f7af, 12)
	if(rounds>10)
		STEP(F, c, d, a, b, SET(10), 0xffff5bb1, 17)
	if(rounds>11)
		STEP(F, b, c, d, a, SET(11), 0x895cd7be, 22)
	if(rounds>12)
		STEP(F, a, b, c, d, SET(12), 0x6b901122, 7)
	if(rounds>13)
		STEP(F, d, a, b, c, SET(13), 0xfd987193, 12)
	if(rounds>14)
		STEP(F, c, d, a, b, SET(14), 0xa679438e, 17)
	if(rounds>15)
		STEP(F, b, c, d, a, SET(15), 0x49b40821, 22)

/* Round 2 */
	if(rounds>16)
		STEP(G, a, b, c, d, GET(1), 0xf61e2562, 5)
	if(rounds>17)
		STEP(G, d, a, b, c, GET(6), 0xc040b340, 9)
	if(rounds>18)
		STEP(G, c, d, a, b, GET(11), 0x265e5a51, 14)
	if(rounds>19)
		STEP(G, b, c, d, a, GET(0), 0xe9b6c7aa, 20)
	if(rounds>20)
		STEP(G, a, b, c, d, GET(5), 0xd62f105d, 5)
	if(rounds>21)
		STEP(G, d, a, b, c, GET(10), 0x02441453, 9)
	if(rounds>22)
		STEP(G, c, d, a, b, GET(15), 0xd8a1e681, 14)
	if(rounds>23)
		STEP(G, b, c, d, a, GET(4), 0xe7d3fbc8, 20)
	if(rounds>24)
		STEP(G, a, b, c, d, GET(9), 0x21e1cde6, 5)
	if(rounds>25)
		STEP(G, d, a, b, c, GET(14), 0xc33707d6, 9)
	if(rounds>26)
		STEP(G, c, d, a, b, GET(3), 0xf4d50d87, 14)
	if(rounds>27)
		STEP(G, b, c, d, a, GET(8), 0x455a14ed, 20)
	if(rounds>28)
		STEP(G, a, b, c, d, GET(13), 0xa9e3e905, 5)
	if(rounds>29)
		STEP(G, d, a, b, c, GET(2), 0xfcefa3f8, 9)
	if(rounds>30)
		STEP(G, c, d, a, b, GET(7), 0x676f02d9, 14)
	if(rounds>31)
		STEP(G, b, c, d, a, GET(12), 0x8d2a4c8a, 20)


/* Round 3 */

	if(rounds>32)
		STEP(H, a, b, c, d, GET(5), 0xfffa3942, 4)
	if(rounds>33)
		STEP(H, d, a, b, c, GET(8), 0x8771f681, 11)
	if(rounds>34)
		STEP(H, c, d, a, b, GET(11), 0x6d9d6122, 16)
	if(rounds>35)
		STEP(H, b, c, d, a, GET(14), 0xfde5380c, 23)
	if(rounds>36)
		STEP(H, a, b, c, d, GET(1), 0xa4beea44, 4)
	if(rounds>37)
		STEP(H, d, a, b, c, GET(4), 0x4bdecfa9, 11)
	if(rounds>38)
		STEP(H, c, d, a, b, GET(7), 0xf6bb4b60, 16)
	if(rounds>39)
		STEP(H, b, c, d, a, GET(10), 0xbebfbc70, 23)
	if(rounds>40)
		STEP(H, a, b, c, d, GET(13), 0x289b7ec6, 4)
	if(rounds>41)
		STEP(H, d, a, b, c, GET(0), 0xeaa127fa, 11)
	if(rounds>42)
		STEP(H, c, d, a, b, GET(3), 0xd4ef3085, 16)
	if(rounds>43)
		STEP(H, b, c, d, a, GET(6), 0x04881d05, 23)
	if(rounds>44)
		STEP(H, a, b, c, d, GET(9), 0xd9d4d039, 4)
	if(rounds>45)
		STEP(H, d, a, b, c, GET(12), 0xe6db99e5, 11)
	if(rounds>46)
		STEP(H, c, d, a, b, GET(15), 0x1fa27cf8, 16)
	if(rounds>47)
		STEP(H, b, c, d, a, GET(2), 0xc4ac5665, 23)
 
/* Round 4 */
	if(rounds>48)
		STEP(I, a, b, c, d, GET(0), 0xf4292244, 6)
	if(rounds>49)
		STEP(I, d, a, b, c, GET(7), 0x432aff97, 10)
	if(rounds>50)
		STEP(I, c, d, a, b, GET(14), 0xab9423a7, 15)
	if(rounds>51)
		STEP(I, b, c, d, a, GET(5), 0xfc93a039, 21)
	if(rounds>52)
		STEP(I, a, b, c, d, GET(12), 0x655b59c3, 6)
	if(rounds>53)
		STEP(I, d, a, b, c, GET(3), 0x8f0ccc92, 10)
	if(rounds>54)
		STEP(I, c, d, a, b, GET(10), 0xffeff47d, 15)
	if(rounds>55)
		STEP(I, b, c, d, a, GET(1), 0x85845dd1, 21)
	if(rounds>56)
		STEP(I, a, b, c, d, GET(8), 0x6fa87e4f, 6)
	if(rounds>57)
		STEP(I, d, a, b, c, GET(15), 0xfe2ce6e0, 10)
	if(rounds>58)
		STEP(I, c, d, a, b, GET(6), 0xa3014314, 15)
	if(rounds>59)
		STEP(I, b, c, d, a, GET(13), 0x4e0811a1, 21)
	if(rounds>60)
		STEP(I, a, b, c, d, GET(4), 0xf7537e82, 6)
	if(rounds>61)
		STEP(I, d, a, b, c, GET(11), 0xbd3af235, 10)
	if(rounds>62)
		STEP(I, c, d, a, b, GET(2), 0x2ad7d2bb, 15)
	if(rounds>63)
		STEP(I, b, c, d, a, GET(9), 0xeb86d391, 21)


		a += saved_a;
		b += saved_b;
		c += saved_c;
		d += saved_d;
 
		ptr += 64;
	} while (size -= 64);
 
	ctx->a = a;
	ctx->b = b;
	ctx->c = c;
	ctx->d = d;
 
	return ptr;
}
 
void MD5_Init(MD5_CTX *ctx)
{
	
	ctx->a = 0x67452301;
	ctx->b = 0xefcdab89;
	ctx->c = 0x98badcfe;
	ctx->d = 0x10325476;
 
	ctx->lo = 0;
	ctx->hi = 0;
}
 
void MD5_Update(MD5_CTX *ctx, void *data, unsigned long size, int rounds)
{
	MD5_u32plus saved_lo;
	unsigned long used, free;
 
	saved_lo = ctx->lo;
	if ((ctx->lo = (saved_lo + size) & 0x1fffffff) < saved_lo) //o que é o 0x1fffffff ??
		ctx->hi++;
	ctx->hi += size >> 29;
 
	used = saved_lo & 0x3f;
 
	if (used) {
		free = 64 - used;
 
		if (size < free) {
			memcpy(&ctx->buffer[used], data, size);
			return;
		}
 
		memcpy(&ctx->buffer[used], data, free);
		data = (unsigned char *)data + free;
		size -= free;
		body(ctx, ctx->buffer, 64, rounds);
	}
 
	if (size >= 64) {
		data = body(ctx, data, size & ~(unsigned long)0x3f, rounds);
		size &= 0x3f;
	}
 
	memcpy(ctx->buffer, data, size);
}
 
void MD5_Final(unsigned char *result, MD5_CTX *ctx, int rounds)
{
	unsigned long used, free;
 
	used = ctx->lo & 0x3f;
 
	ctx->buffer[used++] = 0x80;
 
	free = 64 - used;
 
	if (free < 8) {
		memset(&ctx->buffer[used], 0, free);
		body(ctx, ctx->buffer, 64, rounds);
		used = 0;
		free = 64;
	}
 
	memset(&ctx->buffer[used], 0, free - 8);
 
	ctx->lo <<= 3;
	ctx->buffer[56] = ctx->lo;
	ctx->buffer[57] = ctx->lo >> 8;
	ctx->buffer[58] = ctx->lo >> 16;
	ctx->buffer[59] = ctx->lo >> 24;
	ctx->buffer[60] = ctx->hi;
	ctx->buffer[61] = ctx->hi >> 8;
	ctx->buffer[62] = ctx->hi >> 16;
	ctx->buffer[63] = ctx->hi >> 24;
 
	body(ctx, ctx->buffer, 64, rounds);
 
	result[0] = ctx->a;
	result[1] = ctx->a >> 8;
	result[2] = ctx->a >> 16;
	result[3] = ctx->a >> 24;
	result[4] = ctx->b;
	result[5] = ctx->b >> 8;
	result[6] = ctx->b >> 16;
	result[7] = ctx->b >> 24;
	result[8] = ctx->c;
	result[9] = ctx->c >> 8;
	result[10] = ctx->c >> 16;
	result[11] = ctx->c >> 24;
	result[12] = ctx->d;
	result[13] = ctx->d >> 8;
	result[14] = ctx->d >> 16;
	result[15] = ctx->d >> 24;
 
	memset(ctx, 0, sizeof(*ctx));
}

int main( int argc, char *argv[] )
{
    FILE *fp;
    int i, j;
    MD5_CTX ctx;
    unsigned char md5_sum[16];
	long lSize;
	char* buffer;
	int rounds = atoi(argv[2]);

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
	
	//initiate sha256 array
	MD5_Init ( &ctx );

	//update ctx with the message
	MD5_Update( &ctx, buffer, lSize, rounds);

	//finish the processing and save the has into sha256sum
	MD5_Final( md5_sum, &ctx, rounds);
	
	//print the final result
	for( j = 0; j < 16; j++ )
    {
    	printf( "%02x", md5_sum[j] );
    }

    return( 0 );
}



#endif
