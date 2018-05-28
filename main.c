#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<inttypes.h>
#include<byteswap.h>
#include "crypt.h"

uint64_t key;
int roundnum;
uint8_t subkeys[12][16];

int main(int argc, char* argv[]){
	int roundnum=0;
	if(argc!=2)printf("input ./wsucrypt -d to decrypt\n");

	union block64 input;
	//input.block=plaintext_to_hex("security");
	//input.block=0x7365637572697479;
	//printf("Block %llx\n",input);

	union block64 r;
	
	//open relevant files
	
	FILE* inputf;
	FILE* outputf;
	FILE* keyf;

	if(argc==2){
		if(!(inputf=fopen("cyphertext.txt","r"))){
			exit(0);
		}
		if(!(outputf=fopen("plaintext.txt","w"))){
			exit(0);
		}
	}else{
		if(!(inputf=fopen("plaintext.txt","r"))){
			exit(0);
		}
		if(!(outputf=fopen("cyphertext.txt","w"))){
			exit(0);
		}
	}

	if(!(keyf=fopen("key.txt","r"))){
		exit(0);
	}

	//read key
	char keytxt[16];
	for(int i=0;i<16;i++){
		keytxt[i]=fgetc(keyf);
	}

	key=textblock_to_hex(keytxt);
	set_key(key);
	printf("read key: %llx\n",key);

	//whiten input
	//r.block=whiten(input.block,key);
        //printf("Whitened %08llx\n",r.block);

	//print r[0]s
	for(int i=0;i<4;i++){
		printf("r[%d]=%x ",i,r.fourth[i],i);
	}
	printf("\n");

	//generate subkey table
	for(int i=0;i<16;i++){
		subkeys[0][i]=k(4*i);
		subkeys[1][i]=k((4*i)+1);
		subkeys[2][i]=k((4*i)+2);
		subkeys[3][i]=k((4*i)+3);
		subkeys[4][i]=k(4*i);
		subkeys[5][i]=k((4*i)+1);
		subkeys[6][i]=k((4*i)+2);
		subkeys[7][i]=k((4*i)+3);
		subkeys[8][i]=k(4*i);
		subkeys[9][i]=k((4*i)+1);
		subkeys[10][i]=k((4*i)+2);
		subkeys[11][i]=k((4*i)+3);
	}

	
	for(int i=0;i<16;i++){
		for(int j=0;j<12;j++){
			printf("%x ",subkeys[j][i]);
		}
		printf("\n");
	}

	//loop for file read/write
	int cont=1;
	int stop=0;
	while(cont==1){

		//get block for use in loop
		if(argc==1){
			//encrypt block
			char buffer[8]="";
			for(int i=0;i<8;i++){
				char ch;
				if((ch=fgetc(inputf))!=EOF){
					buffer[i]=ch;
				}else{
					cont=0;
					break;
				}
			}
			printf("buffer= %s\n",buffer);
			input.block=plaintext_to_hex(buffer);
			printf("input= %llx\n",input.block);
			r.block=whiten(input.block,key);
			printf("whitened= %llx\n",r.block);


		}else if(argc==2){
			//decrypt block
			char buffer[16]="";
			for(int i=0;i<16;i++){
				char ch;
				if((ch=fgetc(inputf))!=EOF){
					buffer[i]=ch;
				}else{
					cont=0;
					stop=1;
					break;
				}
			}
			printf("buffer= %s\n",buffer);
			input.block=textblock_to_hex(buffer);
			printf("input= %llx\n",input.block);
			r.block=whiten(input.block,key);
			printf("whitened= %llx\n",r.block);

			if(stop==1){
				break;
			}
		}

		//START OF ALGORITHM

		if(argc==1){
			//encrypt loop
			for(int i=0;i<16;i++){
				uint32_t fs=f(r.fourth[3],r.fourth[2],i);

				uint16_t f0=get_f(fs,0);
				uint16_t f1=get_f(fs,1);

				union block64 nr;
				nr.fourth[3]=r.fourth[1]^f0;
				nr.fourth[2]=r.fourth[0]^f1;
				nr.fourth[1]=r.fourth[3];
				nr.fourth[0]=r.fourth[2];
	
				r.block=nr.block;
			}
		}else if(argc==2){
			//decrpypt loop
			for(int i=15;i>=0;i--){
				uint32_t fs=f(r.fourth[3],r.fourth[2],i);

	                        uint16_t f0=get_f(fs,0);
	                        uint16_t f1=get_f(fs,1);

	                        union block64 nr;
	                        nr.fourth[3]=r.fourth[1]^f0;
	                        nr.fourth[2]=r.fourth[0]^f1;
	                        nr.fourth[1]=r.fourth[3];
	                        nr.fourth[0]=r.fourth[2];

	                        r.block=nr.block;
			}
		}
		union block64 y;
		y.fourth[3]=r.fourth[1];
		y.fourth[2]=r.fourth[0];
		y.fourth[1]=r.fourth[3];
		y.fourth[0]=r.fourth[2];

		y.block=whiten(y.block,key);

		printf("output %llx\n",y.block);

		//END OF ALGORITHM
		if(argc==1){
			write_hex_as_chars(outputf,y.block);
		}else if(argc==2){
			//write_hex_as_plaintext(outputf,y.block);
			write_hex_as_plaintext(outputf,y.block);
		}
	}


	fclose(keyf);
	fclose(inputf);
	fclose(outputf);

	return 0;
}
