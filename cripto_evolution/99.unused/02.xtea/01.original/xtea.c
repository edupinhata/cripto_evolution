#include <stdio.h>
#include <inttypes.h>
#include <stdint.h>

/* take 64 bits of data in v[0] and v[1] and 128 bits of key[0] - key[3] */
 
void encipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], sum=0, delta=0x9E3779B9;
    for (i=0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
    }
    v[0]=v0; v[1]=v1;
}


// algorith to decipher the encrypted message 
void decipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], delta=0x9E3779B9, sum=delta*num_rounds;
    for (i=0; i < num_rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0]=v0; v[1]=v1;
}



int main(int argc, char** argv){

  uint32_t* message = malloc(2*sizeof(uint32_t));
  uint32_t* key = malloc(4*sizeof(uint32_t));

  message[0] = 8127394;
  message[1] = 2172683;
  
  key[0] = 12783;
  key[1] = 12833;
  key[2] = 12433;
  key[3] = 12213;  


  encipher(10, message, key);

  printf("Message1: %u\nMEssage2: %u\n", message[0], message[1]);

  decipher(10, message, key);  printf("Message1: %u\nMEssage2: %u\n", message[0], message[1]);

  return 0;


}
