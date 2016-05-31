/*
 *  FIPS-180-2 compliant SHA-256 implementation
 *
 *  Copyright (C) 2001-2003  Christophe Devine
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <string.h>

#include "sha256.h"

#define GET_UINT32(n,b,i)                       \
{                                               \
    (n) = ( (uint32) (b)[(i)    ] << 24 )       \
        | ( (uint32) (b)[(i) + 1] << 16 )       \
        | ( (uint32) (b)[(i) + 2] <<  8 )       \
        | ( (uint32) (b)[(i) + 3]       );      \
}

#define PUT_UINT32(n,b,i)                       \
{                                               \
    (b)[(i)    ] = (uint8) ( (n) >> 24 );       \
    (b)[(i) + 1] = (uint8) ( (n) >> 16 );       \
    (b)[(i) + 2] = (uint8) ( (n) >>  8 );       \
    (b)[(i) + 3] = (uint8) ( (n)       );       \
}

void sha256_starts( sha256_context *ctx )
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->state[0] = 0x6A09E667;
    ctx->state[1] = 0xBB67AE85;
    ctx->state[2] = 0x3C6EF372;
    ctx->state[3] = 0xA54FF53A;
    ctx->state[4] = 0x510E527F;
    ctx->state[5] = 0x9B05688C;
    ctx->state[6] = 0x1F83D9AB;
    ctx->state[7] = 0x5BE0CD19;
}


void sha256_process( sha256_context *ctx, uint8 data[64], int rounds )
{
    uint32 temp1, temp2, W[64];
    uint32 A, B, C, D, E, F, G, H;

    GET_UINT32( W[0],  data,  0 );
    GET_UINT32( W[1],  data,  4 );
    GET_UINT32( W[2],  data,  8 );
    GET_UINT32( W[3],  data, 12 );
    GET_UINT32( W[4],  data, 16 );
    GET_UINT32( W[5],  data, 20 );
    GET_UINT32( W[6],  data, 24 );
    GET_UINT32( W[7],  data, 28 );
    GET_UINT32( W[8],  data, 32 );
    GET_UINT32( W[9],  data, 36 );
    GET_UINT32( W[10], data, 40 );
    GET_UINT32( W[11], data, 44 );
    GET_UINT32( W[12], data, 48 );
    GET_UINT32( W[13], data, 52 );
    GET_UINT32( W[14], data, 56 );
    GET_UINT32( W[15], data, 60 );

#define  SHR(x,n) ((x & 0xFFFFFFFF) >> n)
#define ROTR(x,n) (SHR(x,n) | (x << (32 - n)))

#define S0(x) (ROTR(x, 7) ^ ROTR(x,18) ^  SHR(x, 3))
#define S1(x) (ROTR(x,17) ^ ROTR(x,19) ^  SHR(x,10))

#define S2(x) (ROTR(x, 2) ^ ROTR(x,13) ^ ROTR(x,22))
#define S3(x) (ROTR(x, 6) ^ ROTR(x,11) ^ ROTR(x,25))

#define F0(x,y,z) ((x & y) | (z & (x | y)))
#define F1(x,y,z) (z ^ (x & (y ^ z)))

#define R(t)                                    \
(                                               \
    W[t] = S1(W[t -  2]) + W[t -  7] +          \
           S0(W[t - 15]) + W[t - 16]            \
)

#define P(a,b,c,d,e,f,g,h,x,K)                  \
{                                               \
    temp1 = h + S3(e) + F1(e,f,g) + K + x;      \
    temp2 = S2(a) + F0(a,b,c);                  \
    d += temp1; h = temp1 + temp2;              \
}

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];

	if(rounds>0)
	    P( A, B, C, D, E, F, G, H, W[ 0], 0x428A2F98 );
    if(rounds>1)
		P( H, A, B, C, D, E, F, G, W[ 1], 0x71374491 );
	if(rounds>2)
	    P( G, H, A, B, C, D, E, F, W[ 2], 0xB5C0FBCF );
    if(rounds>3)
		P( F, G, H, A, B, C, D, E, W[ 3], 0xE9B5DBA5 );
	if(rounds>4)
	    P( E, F, G, H, A, B, C, D, W[ 4], 0x3956C25B );
    if(rounds>5)
		P( D, E, F, G, H, A, B, C, W[ 5], 0x59F111F1 );
	if(rounds>6)
	    P( C, D, E, F, G, H, A, B, W[ 6], 0x923F82A4 );
	if(rounds>7)
	    P( B, C, D, E, F, G, H, A, W[ 7], 0xAB1C5ED5 );
    if(rounds>8)
		P( A, B, C, D, E, F, G, H, W[ 8], 0xD807AA98 );
	if(rounds>9)
		P( H, A, B, C, D, E, F, G, W[ 9], 0x12835B01 );
 	if(rounds>10)
		P( G, H, A, B, C, D, E, F, W[10], 0x243185BE );
 	if(rounds>11)
		P( F, G, H, A, B, C, D, E, W[11], 0x550C7DC3 );
  	if(rounds>12)
		P( E, F, G, H, A, B, C, D, W[12], 0x72BE5D74 );
 	if(rounds>13)
		P( D, E, F, G, H, A, B, C, W[13], 0x80DEB1FE );
  	if(rounds>14)
		P( C, D, E, F, G, H, A, B, W[14], 0x9BDC06A7 );
   	if(rounds>15)
		P( B, C, D, E, F, G, H, A, W[15], 0xC19BF174 );
 	if(rounds>16)
		P( A, B, C, D, E, F, G, H, R(16), 0xE49B69C1 );
 	if(rounds>17)
		P( H, A, B, C, D, E, F, G, R(17), 0xEFBE4786 );
  	if(rounds>18)
		P( G, H, A, B, C, D, E, F, R(18), 0x0FC19DC6 );
 	if(rounds>19)
		P( F, G, H, A, B, C, D, E, R(19), 0x240CA1CC );
  	if(rounds>20)
		P( E, F, G, H, A, B, C, D, R(20), 0x2DE92C6F );
 	if(rounds>21)
		P( D, E, F, G, H, A, B, C, R(21), 0x4A7484AA );
  	if(rounds>22)
		P( C, D, E, F, G, H, A, B, R(22), 0x5CB0A9DC );
 	if(rounds>23)
		P( B, C, D, E, F, G, H, A, R(23), 0x76F988DA );
  	if(rounds>24)
		P( A, B, C, D, E, F, G, H, R(24), 0x983E5152 );
 	if(rounds>25)
		P( H, A, B, C, D, E, F, G, R(25), 0xA831C66D );
  	if(rounds>26)
		P( G, H, A, B, C, D, E, F, R(26), 0xB00327C8 );
 	if(rounds>27)
		P( F, G, H, A, B, C, D, E, R(27), 0xBF597FC7 );
  	if(rounds>28)
		P( E, F, G, H, A, B, C, D, R(28), 0xC6E00BF3 );
 	if(rounds>29)
		P( D, E, F, G, H, A, B, C, R(29), 0xD5A79147 );
  	if(rounds>30)
		P( C, D, E, F, G, H, A, B, R(30), 0x06CA6351 );
 	if(rounds>31)
		P( B, C, D, E, F, G, H, A, R(31), 0x14292967 );
  	if(rounds>32)
		P( A, B, C, D, E, F, G, H, R(32), 0x27B70A85 );
 	if(rounds>33)
		P( H, A, B, C, D, E, F, G, R(33), 0x2E1B2138 );
  	if(rounds>34)
		P( G, H, A, B, C, D, E, F, R(34), 0x4D2C6DFC );
   	if(rounds>35)
		P( F, G, H, A, B, C, D, E, R(35), 0x53380D13 );
 	if(rounds>36)
		P( E, F, G, H, A, B, C, D, R(36), 0x650A7354 );
  	if(rounds>37)
		P( D, E, F, G, H, A, B, C, R(37), 0x766A0ABB );
 	if(rounds>38)
		P( C, D, E, F, G, H, A, B, R(38), 0x81C2C92E );
  	if(rounds>39)
		P( B, C, D, E, F, G, H, A, R(39), 0x92722C85 );
 	if(rounds>40)
		P( A, B, C, D, E, F, G, H, R(40), 0xA2BFE8A1 );
  	if(rounds>41)
		P( H, A, B, C, D, E, F, G, R(41), 0xA81A664B );
 	if(rounds>42)
		P( G, H, A, B, C, D, E, F, R(42), 0xC24B8B70 );
  	if(rounds>43)
		P( F, G, H, A, B, C, D, E, R(43), 0xC76C51A3 );
 	if(rounds>44)
		P( E, F, G, H, A, B, C, D, R(44), 0xD192E819 );
  	if(rounds>45)
		P( D, E, F, G, H, A, B, C, R(45), 0xD6990624 );
 	if(rounds>46)
		P( C, D, E, F, G, H, A, B, R(46), 0xF40E3585 );
     if(rounds>47)
		P( B, C, D, E, F, G, H, A, R(47), 0x106AA070 );
 	if(rounds>48)
		P( A, B, C, D, E, F, G, H, R(48), 0x19A4C116 );
  	if(rounds>49)
		P( H, A, B, C, D, E, F, G, R(49), 0x1E376C08 );
 	if(rounds>50)
		P( G, H, A, B, C, D, E, F, R(50), 0x2748774C );
  	if(rounds>51)
		P( F, G, H, A, B, C, D, E, R(51), 0x34B0BCB5 );
 	if(rounds>52)
		P( E, F, G, H, A, B, C, D, R(52), 0x391C0CB3 );
  	if(rounds>53)
		P( D, E, F, G, H, A, B, C, R(53), 0x4ED8AA4A );
 	if(rounds>54)
		P( C, D, E, F, G, H, A, B, R(54), 0x5B9CCA4F );
  	if(rounds>55)
		P( B, C, D, E, F, G, H, A, R(55), 0x682E6FF3 );
 	if(rounds>56)
		P( A, B, C, D, E, F, G, H, R(56), 0x748F82EE );
  	if(rounds>57)
		P( H, A, B, C, D, E, F, G, R(57), 0x78A5636F );
   	if(rounds>58)
		P( G, H, A, B, C, D, E, F, R(58), 0x84C87814 );
 	if(rounds>59)
		P( F, G, H, A, B, C, D, E, R(59), 0x8CC70208 );
    if(rounds>60)
		P( E, F, G, H, A, B, C, D, R(60), 0x90BEFFFA );
 	if(rounds>61)
		P( D, E, F, G, H, A, B, C, R(61), 0xA4506CEB );
  	if(rounds>62)
		P( C, D, E, F, G, H, A, B, R(62), 0xBEF9A3F7 );
 	if(rounds>63)
		P( B, C, D, E, F, G, H, A, R(63), 0xC67178F2 );

	
    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
    ctx->state[4] += E;
    ctx->state[5] += F;
    ctx->state[6] += G;
    ctx->state[7] += H;
}

void sha256_update( sha256_context *ctx, uint8 *input, uint32 length, int rounds )
{
    uint32 left, fill;

    if( ! length ) return;

    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += length;
    ctx->total[0] &= 0xFFFFFFFF;

    if( ctx->total[0] < length )
        ctx->total[1]++;

    if( left && length >= fill )
    {
        memcpy( (void *) (ctx->buffer + left),
                (void *) input, fill );
        sha256_process( ctx, ctx->buffer, rounds );
        length -= fill;
        input  += fill;
        left = 0;
    }

    while( length >= 64 )
    {
        sha256_process( ctx, input, rounds );
        length -= 64;
        input  += 64;
    }

    if( length )
    {
        memcpy( (void *) (ctx->buffer + left),
                (void *) input, length );
    }
}

static uint8 sha256_padding[64] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void sha256_finish( sha256_context *ctx, uint8 digest[32], int rounds )
{
    uint32 last, padn;
    uint32 high, low;
    uint8 msglen[8];

    high = ( ctx->total[0] >> 29 )
         | ( ctx->total[1] <<  3 );
    low  = ( ctx->total[0] <<  3 );

    PUT_UINT32( high, msglen, 0 );
    PUT_UINT32( low,  msglen, 4 );

    last = ctx->total[0] & 0x3F;
    padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

    sha256_update( ctx, sha256_padding, padn, rounds );
    sha256_update( ctx, msglen, 8, rounds );

    PUT_UINT32( ctx->state[0], digest,  0 );
    PUT_UINT32( ctx->state[1], digest,  4 );
    PUT_UINT32( ctx->state[2], digest,  8 );
    PUT_UINT32( ctx->state[3], digest, 12 );
    PUT_UINT32( ctx->state[4], digest, 16 );
    PUT_UINT32( ctx->state[5], digest, 20 );
    PUT_UINT32( ctx->state[6], digest, 24 );
    PUT_UINT32( ctx->state[7], digest, 28 );
}

//#ifdef TEST

#include <stdlib.h>
#include <stdio.h>

/*
 * those are the standard FIPS-180-2 test vectors
 */
/*
static char *msg[] = 
{
    "abc",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    NULL
};

static char *val[] =
{
    "ba7816bf8f01cfea414140de5dae2223" \
    "b00361a396177a9cb410ff61f20015ad",
    "248d6a61d20638b8e5c026930c3e6039" \
    "a33ce45964ff2167f6ecedd419db06c1",
    "cdc76e5c9914fb9281a1c7e284d73e67" \
    "f1809a48a497200e046d39ccc7112cd0"
};
*/

int main( int argc, char *argv[] )
{
    FILE *fp;
    int i, j;
    char output[65];
    sha256_context ctx;
    unsigned char sha256sum[32];
	long lSize;
	char* buffer;
	unsigned char * enc_msg; //message that will receive the encryption of each part of the message
	char msg_part[32]; //variable that will receive the blocks of message
	int rounds = atoi(argv[2]);

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
	//initiate sha256 array
	sha256_starts ( &ctx );

	while(i<lSize){	
		//printf("lSize: %d\n" , i);
		
			
		//copy part of the message that will be "encrypted"
		//receive 32 bytes = 256 bits
		memcpy(msg_part, buffer, 32);
		//printf("Msg_part: %s\n" , msg_part);

		for(j=0; j<16; j++)
				msg_part[j] = (char)(msg_part[j] ^ sha256sum[j]);


		//update ctx with the message
		sha256_update( &ctx, (uint8 *)msg_part, 32, rounds);

		//finish the processing and save the has into sha256sum
		sha256_finish( &ctx, sha256sum, rounds);

		/*for(j=0; j<32; j++)
				printf("%02x", sha256sum[j]);
		printf("\n\n");*/

		//copy the code to enc_msg
		memcpy(&enc_msg[i], sha256sum, 32);

	/*	
		for(j=0; j<32; j++)
				printf("%02x", enc_msg[j+i]);
		printf("\n\n");*/

		//buffer go to the next position of encryption	
		buffer  += 32;
		i       += 32;
	}


	//print the final result
	for( j = 0; j < lSize; j++ )
    {
    	printf( "%02x", enc_msg[j] );
    }



    return( 0 );
}

//#endif
