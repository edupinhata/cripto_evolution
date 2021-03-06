// Code by: B-Con (http://b-con.us) 
// Released under the GNU GPL 
// MD2 Hash Digest implementation (little endian bit order) 

// Whoever decided that characters should be signed by default deserves to be shot. 
#include <string.h>
#include<stdio.h>
#include<stdlib.h>

#define char unsigned char 



typedef struct { 
   char data[16]; 
   char state[48]; 
   char checksum[16]; 
   int len; 
} MD2_CTX; 


int const NUM_ROUNDS=18;


static char s[256] = { 
   41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
   19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
   76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
   138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
   245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
   148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
   39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
   181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
   150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
   112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
   96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
   85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
   234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
   129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
   8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
   203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
   166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
   31, 26, 219, 153, 141, 51, 159, 17, 131, 20
}; 


void md2_transform(MD2_CTX *ctx, char data[], int num_rounds) 
{  
   int j,k,t; 
   
   //memcpy(&ctx->state[16],data); 
   for (j=0; j < 16; ++j) { 
      ctx->state[j+16] = data[j]; 
      ctx->state[j+32] = (ctx->state[j+16] ^ ctx->state[j]); 
   }  

   t = 0; 
   for (j=0; j < num_rounds; ++j) { 
      for (k=0; k < 48; ++k) { 
         ctx->state[k] ^= s[t]; 
         t = ctx->state[k]; 
      }  
      t = (t+j) & 0xFF; 
   }  
   
   t = ctx->checksum[15]; 
   for (j=0; j < 16; ++j) { 
      ctx->checksum[j] ^= s[data[j] ^ t]; 
      t = ctx->checksum[j]; 
   }  
}  

void md2_init(MD2_CTX *ctx) 
{  
   int i; 
   
   for (i=0; i < 48; ++i) 
      ctx->state[i] = 0; 
   for (i=0; i < 16; ++i) 
      ctx->checksum[i] = 0; 
   ctx->len = 0; 
}  
   
void md2_update(MD2_CTX *ctx, char data[], int len, int num_rounds) 
{  
   int t,i;
   
   for (i=0; i < len; ++i) { 
      ctx->data[ctx->len] = data[i]; 
      ctx->len++; 
      if (ctx->len == 16) { 
         md2_transform(ctx,ctx->data, num_rounds); 
         ctx->len = 0; 
      }
   }      
}  

void md2_final(MD2_CTX *ctx, char hash[], int num_rounds) 
{  
   int to_pad; 
   
   to_pad = 16 - ctx->len; 
   
   while (ctx->len < 16) 
      ctx->data[ctx->len++] = to_pad; 
   
   md2_transform(ctx,ctx->data, num_rounds); 
   md2_transform(ctx,ctx->checksum, num_rounds); 
   
   memcpy(hash,ctx->state,16); 
}


#undef char

int main(int argc, char **argv)
{
	FILE *fp;
	int i, j;
	MD2_CTX ctx;
	unsigned char md2_sum[16];
	long lSize;
	unsigned char* buffer;
	int rounds = atoi(argv[2]);


	fp = fopen( argv[1], "rb");
	if(!fp) perror(argv[1]), exit(1);

	fseek( fp, 0L, SEEK_END);
	lSize = ftell(fp);
	rewind(fp);

	/* allocate memory for entire content */
	buffer = calloc(1, lSize+1);
	if(!buffer) fclose(fp), fputs("memory alloc fails", stderr), exit(1);
	
	/* copy the file into the buffer */
	if( 1!=fread( buffer, lSize, 1, fp) )
			fclose(fp), free(buffer), fputs("entire read fails", stderr), exit(1);


	//initiate md2 array
	md2_init(&ctx);


	//void md2_update(MD2_CTX *ctx, char data[], int len, int num_rounds) 
	md2_update( &ctx, buffer, lSize, rounds);

	//void md2_final(MD2_CTX *ctx, char hash[], int num_rounds) 
	md2_final(&ctx, md2_sum, rounds);
		
	//print the final result
	for(j=0; j<16; j++)
	{
		printf("%02x", md2_sum[j]);
	}


}
