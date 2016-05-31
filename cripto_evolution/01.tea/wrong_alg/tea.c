#include <stdio.h>
#include <stdint.h>
//#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

//encrypt method for tea
void encrypt(uint32_t* v, uint32_t*k, int rounds)
{
  uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
  uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
  uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
  for (i=0; i <rounds; i++) {                       /* basic cycle start */
    sum += delta;
    v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
    v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);  

    //printf("Cicle %d:\nv0: %u\nv1: %u\n", i, v0, v1); /*print each stage of the cicle*/
  }                                              /* end cycle */
  v[0]=v0; v[1]=v1;
  
}//end encrypt


//decrypt method for tea
void decrypt (uint32_t* v, uint32_t* k, int rounds) {
    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;  /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i<rounds; i++) {                         /* basic cycle start */
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;                                   
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}//end decrypt

//rotate an char array to the left one time
char* leftRotateByOne(char *arr){
	int i, size = strlen(arr);
	char tmp = arr[0];
	char *arr_tmp = malloc(strlen(arr));

	for(i=0;i<(size-1);i++){
		arr_tmp[i] = arr[i+1];
	}
	
	arr_tmp[size-1] = tmp;
	return arr_tmp;
}

//rotate all the elements to the left rotation times
char* leftRotate(char *word, int rotation){
	int i;

	for(i=0;i<rotation;i++){
		word = leftRotateByOne(word);
	}
	return word;
}



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
	//strcat(enc_msg, message_char);
	memcpy(&enc_msg[(j-1)*8], message_char, 8);
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
	  //strcat(enc_msg, message_char);
	  memcpy(&enc_msg[(j-1)*8], message_char, 8);

  }
  free(message_part);
  return enc_msg;
}


/*
char* encrypt_msg(char* message, char* key, int round){
   //ARGUMENTS	
  //==========================
 
  char *enc_msg = malloc(strlen(message)); //will be returned with encrypted message
  char * message_part = malloc(2*sizeof(uint32_t)); //will hold the parts of the message
  int i,j; //iterator key

  //LOGIC PART
  //============================

  //loop for the whole message

  for(j=1;j<=((int)strlen(message)/8);j++){

	  //get 8 char at time to the message
	  //strncpy(message_part, leftRotate(message, (j-1)*8),  8);
	  memcpy(message_part, message[(j-1)*8], 8);	

	  //transform char to uint32_t to be processed by the functions 
	  uint32_t * message_int = (uint32_t *)message_part;
	  uint32_t * key_int = (uint32_t *)key;

	  encrypt(message_int, key_int, round);

	  char * message_char = (char*)message_int;
	  strcat(enc_msg, message_char);
  }

  return enc_msg;
}


char* decrypt_msg(char* message, char* key, int round){
   //ARGUMENTS	
  //==========================
 
  char *enc_msg = malloc(strlen(message)); //will be returned with encrypted message
  char * message_part = malloc(2*sizeof(uint32_t)); //will hold the parts of the message
  int i,j; //iterator key


  //LOGIC PART
  //============================

  //loop for the whole message

  for(j=1;j<=((int)strlen(message)/8);j++){

	  //get 8 char at time to the message
	  //strncpy(message_part, leftRotate(message, (j-1)*8),  8);
	  memcpy(message_part, message[(j-1)*8], 8);

	  //transform char to uint32_t to be processed by the functions 
	  uint32_t * message_int = (uint32_t *)message_part;
	  uint32_t * key_int = (uint32_t *)key;

	  decrypt(message_int, key_int, round);

	  char * message_char = (char*)message_int;
	  strcat(enc_msg, message_char);

  }

  return enc_msg;
}
*/

int main(int argc, char** argv){
	char * key = (char*)argv[2];

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
	encrypt_msg(buffer, enc_msg, key, lSize, atoi(argv[3]));

	char * dec_msg = calloc(1, lSize+1);
	decrypt_msg(enc_msg, dec_msg, key, lSize, atoi(argv[3]));

	free(buffer);

//	printf("%s", enc_msg);
	printf("%s", dec_msg);



	return 0;
}


