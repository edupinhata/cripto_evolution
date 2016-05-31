#include <stdio.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* take 64 bits of data in v[0] and v[1] and 128 bits of key[0] - key[3] */
 
void encrypt(uint32_t v[2], uint32_t const key[4], int rounds) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], sum=0, delta=0x9E3779B9;
    for (i=0; i < rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
    }
    v[0]=v0; v[1]=v1;
}


// algorith to decipher the encrypted message 
void decrypt(uint32_t v[2], uint32_t const key[4], int rounds) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], delta=0x9E3779B9, sum=delta*rounds;
    for (i=0; i < rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0]=v0; v[1]=v1;
}


//rotate an char array to the left one time
char* leftRotateByOne(char *arr, char* arr_tmp, long msg_size){
	int i;
	char tmp = arr[0];
	//printf("tmp char: %c\n" , tmp);
	//char *arr_tmp = calloc(1, msg_size+1);

	for(i=0;i<(msg_size-2);i++){
		arr_tmp[i] = arr[i+1];
		//printf("Message: %s\n", arr_tmp);
	}
	
	arr_tmp[msg_size-2] = tmp;
	//printf("arr_tmp[%ld]: %c\n",msg_size-1, arr_tmp[msg_size-1]);
	//printf("Array  : %s\n",arr_tmp);
	return arr_tmp;
}

//rotate all the elements to the left rotation times
char* leftRotate(char *word, int rotation, long msg_size){
	int i;
	char *arr_tmp = calloc(1, msg_size+1);	

	for(i=0;i<rotation;i++){
		word = leftRotateByOne(word, arr_tmp,  msg_size);
		//printf("%s", word);
	}
	free(arr_tmp);
	return word;
}

//#define SHR(x, n) ((x & 0xFFFFFFFF) >> n)


char* encrypt_msg(char* message, char* enc_msg,  char* key, long msg_size, int round){
   //ARGUMENTS	
  //==========================
  //printf("Allocating memory\n"); 
  //char *enc_msg = calloc(1, msg_size+1); //will be returned with encrypted message
  char * message_part = calloc(1, 2*sizeof(uint32_t)); //will hold the parts of the message
  int i,j; //iterator key

  //printf("Memory allocated");

  //LOGIC PART
  //============================

  //printf("Mesage size: %ld", msg_size);
  //loop for the whole message
  for(j=1;j<=(msg_size/8);j++){
	//printf("Running\n");
	//get 8 char at time to the message
	//memcpy(message_part, leftRotate(message, (j-1)*8, msg_size),  8);	
	memcpy(message_part, &message[(j-1)*8], 8);  
	
	//printf("Message: %s", &message[(j-1)*8]);

	//transform char to uint32_t to be processed by the functions 
	uint32_t * message_int = (uint32_t *)message_part;
	uint32_t * key_int = (uint32_t *)key;
		
	encrypt(message_int, key_int, round);

	char * message_char = (char*)message_int;
	strcat(enc_msg, message_char);
  }
  free(message_part);
  return enc_msg;
}


char* decrypt_msg(char* message, char*enc_msg,  char* key, long msg_size, int round){
   //ARGUMENTS	
  //==========================
 
  //char *enc_msg = calloc(1, msg_size+1); //will be returned with encrypted message
  char * message_part = malloc(2*sizeof(uint32_t)); //will hold the parts of the message
  int i,j; //iterator key


  //LOGIC PART
  //============================

  //loop for the whole message

  for(j=1;j<=(msg_size/8);j++){

	  //get 8 char at time to the message
	  //memcpy(message_part, leftRotate(message, (j-1)*8, msg_size),  8);
	  memcpy(message_part, &message[(j-1)*8], 8);

	  //transform char to uint32_t to be processed by the functions 
	  uint32_t * message_int = (uint32_t *)message_part;
	  uint32_t * key_int = (uint32_t *)key;

	  decrypt(message_int, key_int, round);

	  char * message_char = (char*)message_int;
	  strcat(enc_msg, message_char);

  }
  free(message_part);
  return enc_msg;
}



int main(int argc, char** argv){
	char * key = argv[2];

	FILE *fp;
	long lSize;
	char *buffer;

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
	

	char * enc_msg = calloc(1, lSize+1);
	encrypt_msg(buffer,enc_msg,  key, lSize, atoi(argv[3]));
	//printf("%s", enc_msg);

	char * dec_msg = calloc(1, lSize+1); 
	decrypt_msg(enc_msg, dec_msg, key, lSize, atoi(argv[3]));
	printf("%s", dec_msg);	

		
	fclose(fp);
	free(buffer); free(enc_msg); free(dec_msg);

	
  	return 0;


}
