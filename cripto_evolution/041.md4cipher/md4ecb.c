/*
 * This is an OpenSSL-compatible implementation of the RSA Data Security, Inc.
 * #include <stdlib.h>
 * #include <stdio.h>#include <stdlib.h>
 * #include <stdio.h>#include <stdlib.h>
 * #include <stdio.h>#include <stdlib.h>
 * #include <stdio.h>#include <stdlib.h>
 * #include <stdio.h>MD4 Message-Digest Algorithm (RFC 1320).
 *
 * Homepage:
 * http://openwall.info/wiki/people/solar/software/public-domain-source-code/md4
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
#include <stdlib.h>
#include <stdio.h>
#include "md4.h"

/*
 * The basic MD4 functions.
 *
 * F and G are optimized compared to their RFC 1320 definitions, with the
 * optimization for F borrowed from Colin Plumb's MD5 implementation.
 */
#define F(x, y, z)			((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)			(((x) & ((y) | (z))) | ((y) & (z)))
#define H(x, y, z)			((x) ^ (y) ^ (z))

/*
 * The MD4 transformation for all three rounds.
 */
#define STEP(f, a, b, c, d, x, s) \
	(a) += f((b), (c), (d)) + (x); \
	(a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s))));

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
	(*(MD4_u32plus *)&ptr[(n) * 4])
#define GET(n) \
	SET(n)
#else
#define SET(n) \
	(ctx->block[(n)] = \
	(MD4_u32plus)ptr[(n) * 4] | \
	((MD4_u32plus)ptr[(n) * 4 + 1] << 8) | \
	((MD4_u32plus)ptr[(n) * 4 + 2] << 16) | \
	((MD4_u32plus)ptr[(n) * 4 + 3] << 24))
#define GET(n) \
	(ctx->block[(n)])
#endif

/*
 * This processes one or more 64-byte data blocks, but does NOT update
 * the bit counters.  There are no alignment requirements.
 */
static const void *body(MD4_CTX *ctx, const void *data, unsigned long size, int rounds)
{
	const unsigned char *ptr;
	MD4_u32plus a, b, c, d;
	MD4_u32plus saved_a, saved_b, saved_c, saved_d;

	ptr = (const unsigned char *)data;

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
			STEP(F, a, b, c, d, SET(0), 3)
		if(rounds>1)
			STEP(F, d, a, b, c, SET(1), 7)
		if(rounds>2)
			STEP(F, c, d, a, b, SET(2), 11)
		if(rounds>3)
			STEP(F, b, c, d, a, SET(3), 19)
		if(rounds>4)
			STEP(F, a, b, c, d, SET(4), 3)
		if(rounds>5)
			STEP(F, d, a, b, c, SET(5), 7)
		if(rounds>6)
			STEP(F, c, d, a, b, SET(6), 11)
		if(rounds>7)
			STEP(F, b, c, d, a, SET(7), 19)
		if(rounds>8)
			STEP(F, a, b, c, d, SET(8), 3)
		if(rounds>9)
			STEP(F, d, a, b, c, SET(9), 7)
		if(rounds>10)
			STEP(F, c, d, a, b, SET(10), 11)
		if(rounds>11)
			STEP(F, b, c, d, a, SET(11), 19)
		if(rounds>12)
			STEP(F, a, b, c, d, SET(12), 3)
		if(rounds>13)
			STEP(F, d, a, b, c, SET(13), 7)
		if(rounds>14)
			STEP(F, c, d, a, b, SET(14), 11)
		if(rounds>15)
			STEP(F, b, c, d, a, SET(15), 19)

/* Round 2 */
		if(rounds>16)
			STEP(G, a, b, c, d, GET(0) + 0x5a827999, 3)
		if(rounds>17)
			STEP(G, d, a, b, c, GET(4) + 0x5a827999, 5)
		if(rounds>18)
			STEP(G, c, d, a, b, GET(8) + 0x5a827999, 9)
		if(rounds>19)
			STEP(G, b, c, d, a, GET(12) + 0x5a827999, 13)
		if(rounds>20)
			STEP(G, a, b, c, d, GET(1) + 0x5a827999, 3)
		if(rounds>21)
			STEP(G, d, a, b, c, GET(5) + 0x5a827999, 5)
		if(rounds>22)
			STEP(G, c, d, a, b, GET(9) + 0x5a827999, 9)
		if(rounds>23)
			STEP(G, b, c, d, a, GET(13) + 0x5a827999, 13)
		if(rounds>24)
			STEP(G, a, b, c, d, GET(2) + 0x5a827999, 3)
		if(rounds>25)
			STEP(G, d, a, b, c, GET(6) + 0x5a827999, 5)
		if(rounds>26)
			STEP(G, c, d, a, b, GET(10) + 0x5a827999, 9)
		if(rounds>27)
			STEP(G, b, c, d, a, GET(14) + 0x5a827999, 13)
		if(rounds>28)
			STEP(G, a, b, c, d, GET(3) + 0x5a827999, 3)
		if(rounds>29)
			STEP(G, d, a, b, c, GET(7) + 0x5a827999, 5)
		if(rounds>30)
			STEP(G, c, d, a, b, GET(11) + 0x5a827999, 9)
		if(rounds>31)
			STEP(G, b, c, d, a, GET(15) + 0x5a827999, 13)

/* Round 3 */
		if(rounds>32)
			STEP(H, a, b, c, d, GET(0) + 0x6ed9eba1, 3)
		if(rounds>33)
			STEP(H, d, a, b, c, GET(8) + 0x6ed9eba1, 9)
		if(rounds>34)
			STEP(H, c, d, a, b, GET(4) + 0x6ed9eba1, 11)
		if(rounds>35)
			STEP(H, b, c, d, a, GET(12) + 0x6ed9eba1, 15)
		if(rounds>36)
			STEP(H, a, b, c, d, GET(2) + 0x6ed9eba1, 3)
		if(rounds>37)
			STEP(H, d, a, b, c, GET(10) + 0x6ed9eba1, 9)
		if(rounds>38)
			STEP(H, c, d, a, b, GET(6) + 0x6ed9eba1, 11)
		if(rounds>39)
			STEP(H, b, c, d, a, GET(14) + 0x6ed9eba1, 15)
		if(rounds>40)
			STEP(H, a, b, c, d, GET(1) + 0x6ed9eba1, 3)
		if(rounds>41)
			STEP(H, d, a, b, c, GET(9) + 0x6ed9eba1, 9)
		if(rounds>42)
			STEP(H, c, d, a, b, GET(5) + 0x6ed9eba1, 11)
		if(rounds>43)
			STEP(H, b, c, d, a, GET(13) + 0x6ed9eba1, 15)
		if(rounds>44)
			STEP(H, a, b, c, d, GET(3) + 0x6ed9eba1, 3)
		if(rounds>45)
			STEP(H, d, a, b, c, GET(11) + 0x6ed9eba1, 9)
		if(rounds>46)
			STEP(H, c, d, a, b, GET(7) + 0x6ed9eba1, 11)
		if(rounds>47)
			STEP(H, b, c, d, a, GET(15) + 0x6ed9eba1, 15)

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

void MD4_Init(MD4_CTX *ctx)
{
	ctx->a = 0x67452301;
	ctx->b = 0xefcdab89;
	ctx->c = 0x98badcfe;
	ctx->d = 0x10325476;

	ctx->lo = 0;
	ctx->hi = 0;
}

void MD4_Update(MD4_CTX *ctx, const void *data, unsigned long size, int rounds)
{
	MD4_u32plus saved_lo;
	unsigned long used, available;

	saved_lo = ctx->lo;
	if ((ctx->lo = (saved_lo + size) & 0x1fffffff) < saved_lo)
		ctx->hi++;
	ctx->hi += size >> 29;

	used = saved_lo & 0x3f;

	if (used) {
		available = 64 - used;

		if (size < available) {
			memcpy(&ctx->buffer[used], data, size);
			return;
		}

		memcpy(&ctx->buffer[used], data, available);
		data = (const unsigned char *)data + available;
		size -= available;
		body(ctx, ctx->buffer, 64, rounds);
	}

	if (size >= 64) {
		data = body(ctx, data, size & ~(unsigned long)0x3f, rounds);
		size &= 0x3f;
	}

	memcpy(ctx->buffer, data, size);
}

void MD4_Final(unsigned char *result, MD4_CTX *ctx, int rounds)
{
	unsigned long used, available;

	used = ctx->lo & 0x3f;

	ctx->buffer[used++] = 0x80;

	available = 64 - used;

	if (available < 8) {
		memset(&ctx->buffer[used], 0, available);
		body(ctx, ctx->buffer, 64, rounds);
		used = 0;
		available = 64;
	}

	memset(&ctx->buffer[used], 0, available - 8);

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

int main(int argc, char**argv){
    FILE *fp;
    int i, j;
    MD4_CTX ctx;
    unsigned char md5_sum[16];
	long lSize;
	unsigned char* buffer;
	int rounds = atoi(argv[2]);
	unsigned char* enc_msg; //message that will receive the encryption of each part of the message.
	unsigned char msg_part[16];

	fp = fopen ( argv[1] , "rb" );
	if( !fp ) perror(argv[1]),exit(1);

	fseek( fp , 0L , SEEK_END);
	lSize = ftell( fp );
	rewind( fp );

	/* allocate memory for entire content */
	buffer = calloc( 1, lSize+1 );
	enc_msg = calloc(1, lSize+1);
	if( !buffer ) fclose(fp),fputs("memory alloc fails",stderr),exit(1);

	/* copy the file into the buffer */
	if( 1!=fread( buffer, lSize, 1 , fp) )
	  fclose(fp),free(buffer),fputs("entire read fails",stderr),exit(1);

	i=0;

	while(i<=lSize){

		//copy part of the message that will be "encrypted"
		////receive 16 bytes = 128 bits
		memcpy(msg_part, buffer, 16);
		
		//initiate sha256 array
		MD4_Init ( &ctx );
		
		//update ctx with the message
		MD4_Update( &ctx, msg_part, 16, rounds);

		//finish the processing and save the has into sha256sum
		MD4_Final( md5_sum, &ctx, rounds);

		memcpy(&enc_msg[i], md5_sum, 16);

		buffer += 16;
		i      += 16;


	}


		//print the final result
		for( j = 0; j < lSize; j++ )
   		 {
    		printf( "%02x", enc_msg[j] );
    	}


    return( 0 );


}


#endif
