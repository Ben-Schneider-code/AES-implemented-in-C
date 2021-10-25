#include <stdlib.h>
#include <stdio.h>
#include "sbox.h"
#include <string.h>

#define WORD_SIZE 32

typedef struct {
    __uint8_t arr[11][4][4];
} keyExpansion;

typedef struct {
    __uint8_t arr[4][4];
} State;

void loadFile(char*, __uint8_t*);
keyExpansion KeyExpansion();
__uint32_t cycShift(__uint32_t input, int shiftSize);
__uint8_t S(__uint8_t input);
__uint32_t combine(__uint8_t m1,__uint8_t m2,__uint8_t m3,__uint8_t m4);
__uint32_t S32(__uint32_t input);
__uint8_t xtime(__uint8_t x);
__uint8_t mult(__uint8_t x, __uint32_t y);
State getInitialState();
State MixColumns(State oldState);
State ShiftRows(State oldState);
State xor(State s, keyExpansion k, int keynum);
State SubBytes(State s);
void printState(State s);
State encrypt(State state);
void printInputs();
__uint8_t invS(__uint8_t input);
State InvSubBytes(State s);
State InvShiftRows(State oldState);
State InvMixColumns(State oldState);
State decrypt(State state);

__uint8_t key[16];

__uint8_t msg[16];

__uint32_t C[11] = {0xFFFFFFFF,0x01000000,
0x02000000, 0x04000000,
0x08000000, 0x10000000,
0x20000000, 0x40000000,
0x80000000, 0x1b000000,
0x36000000};

int main(int argc, char** argv){

    if(argc < 3){
        printf("Not enough cmd line arguments!");
        exit(1);
    }

    loadFile(argv[1], msg);
    loadFile(argv[2], key);

    printInputs();

    State state = getInitialState();
    
    state = encrypt(state);

    printf("\n\nCiphertext: \n");
    printState(state);
    printf("\n\n");

    state = decrypt(state);

    printf("\n\nPlaintext: \n");
    printState(state);
    printf("\nend of processing\n");
    return 0;

}

State decrypt(State state){

     //decrypt state
    keyExpansion roundKeys = KeyExpansion();

    printf("\nDecryption Process\n");

    state = xor(state, roundKeys, 10);
    state = InvShiftRows(state);
    state = InvSubBytes(state);


    for(int r = 9; r > 0; r--){
        
        state = xor(state, roundKeys, r);
        state = InvMixColumns(state);
        printf("\nState after %d call(s) to InvMixColumns:  \n", 10 - r);
        printState(state);
        fflush(stdout);

        state = InvShiftRows(state);
        state = InvSubBytes(state);

    }

    state = xor(state, roundKeys, 0); //the final bit of magic 

    return state;
}

void printInputs(){
    printf("Plaintext:\n");
    for(int i = 0; i < 16; i++)
        printf("%02x  ", msg[i]);

    printf("\nkey:\n");
    for(int i = 0; i < 16; i++)
        printf("%02x  ", key[i]);

    printf("\n\n\n");
}

State encrypt(State state){
    //AES ALGORITHIM
    keyExpansion roundKeys = KeyExpansion();
    state = xor(state, roundKeys, 0);
    
    printf("\nEncryption Process\n");

    for(int r = 1; r <= 10; r++){
        
        state = SubBytes(state);
        state = ShiftRows(state);

        if(r <= 9){
            state = MixColumns(state);
            printf("\nState after %d call(s) to MixColumns:  \n", r);
            printState(state);
        }
        state = xor(state, roundKeys, r);

    }
    return state;
}

void printState(State s){

    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++)
            printf("%02x ", s.arr[j][i]);
        printf("  ");
    }
}

State SubBytes(State s){
    State newState;

    for(int i = 0; i < 4; i++)
        for(int j = 0; j < 4; j++)
            newState.arr[i][j] = S(s.arr[i][j]);

    return newState;
}

State InvSubBytes(State s){
    State newState;

    for(int i = 0; i < 4; i++)
        for(int j = 0; j < 4; j++)
            newState.arr[i][j] = invS(s.arr[i][j]);

    return newState;
}

State xor(State s, keyExpansion k, int keynum){
    State newState;

    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            newState.arr[i][j] = s.arr[i][j] ^ k.arr[keynum][i][j];
    return newState;
}

State ShiftRows(State oldState){
    State newState;
    newState.arr[0][0] = oldState.arr[0][0];
    newState.arr[0][1] = oldState.arr[0][1];
    newState.arr[0][2] = oldState.arr[0][2];
    newState.arr[0][3] = oldState.arr[0][3];

    newState.arr[1][0] = oldState.arr[1][1];
    newState.arr[1][1] = oldState.arr[1][2];
    newState.arr[1][2] = oldState.arr[1][3];
    newState.arr[1][3] = oldState.arr[1][0];

    newState.arr[2][0] = oldState.arr[2][2];
    newState.arr[2][1] = oldState.arr[2][3];
    newState.arr[2][2] = oldState.arr[2][0];
    newState.arr[2][3] = oldState.arr[2][1];

    newState.arr[3][0] = oldState.arr[3][3];
    newState.arr[3][1] = oldState.arr[3][0];
    newState.arr[3][2] = oldState.arr[3][1];
    newState.arr[3][3] = oldState.arr[3][2];

    return newState;
}

State InvShiftRows(State oldState){
    State newState;
    newState.arr[0][0] = oldState.arr[0][0];
    newState.arr[0][1] = oldState.arr[0][1];
    newState.arr[0][2] = oldState.arr[0][2];
    newState.arr[0][3] = oldState.arr[0][3];

    newState.arr[1][0] = oldState.arr[1][3];
    newState.arr[1][1] = oldState.arr[1][0];
    newState.arr[1][2] = oldState.arr[1][1];
    newState.arr[1][3] = oldState.arr[1][2];

    newState.arr[2][0] = oldState.arr[2][2];
    newState.arr[2][1] = oldState.arr[2][3];
    newState.arr[2][2] = oldState.arr[2][0];
    newState.arr[2][3] = oldState.arr[2][1];

    newState.arr[3][0] = oldState.arr[3][1];
    newState.arr[3][1] = oldState.arr[3][2];
    newState.arr[3][2] = oldState.arr[3][3];
    newState.arr[3][3] = oldState.arr[3][0];

    return newState;
}

State InvMixColumns(State oldState){

    State newState;

    for(int col = 0; col < 4; col++){ //for each column
        newState.arr[0][col] = mult(oldState.arr[0][col], 0x0e) ^ 
        mult(oldState.arr[1][col], 0x0b) ^ 
        mult(oldState.arr[2][col], 0x0d) ^ 
        mult(oldState.arr[3][col],0x09);

        newState.arr[1][col] = mult(oldState.arr[0][col], 0x09) ^ 
        mult(oldState.arr[1][col], 0x0e) ^ 
        mult(oldState.arr[2][col], 0x0b) ^ 
        mult(oldState.arr[3][col],0x0d);

        newState.arr[2][col] = mult(oldState.arr[0][col], 0x0d) ^ 
        mult(oldState.arr[1][col], 0x09) ^ 
        mult(oldState.arr[2][col], 0x0e) ^ 
        mult(oldState.arr[3][col],0x0b);

        newState.arr[3][col] = mult(oldState.arr[0][col], 0x0b) ^ 
        mult(oldState.arr[1][col], 0x0d) ^ 
        mult(oldState.arr[2][col], 0x09) ^ 
        mult(oldState.arr[3][col],0x0e);
    }

    return newState;
}

State MixColumns(State oldState){

    State newState;

    for(int col = 0; col < 4; col++){ //for each column
        newState.arr[0][col] = mult(oldState.arr[0][col], 0x02) ^ 
        mult(oldState.arr[1][col], 0x03) ^ 
        mult(oldState.arr[2][col], 0x01) ^ 
        mult(oldState.arr[3][col],0x01);

        newState.arr[1][col] = mult(oldState.arr[0][col], 0x01) ^ 
        mult(oldState.arr[1][col], 0x02) ^ 
        mult(oldState.arr[2][col], 0x03) ^ 
        mult(oldState.arr[3][col],0x01);

        newState.arr[2][col] = mult(oldState.arr[0][col], 0x01) ^ 
        mult(oldState.arr[1][col], 0x01) ^ 
        mult(oldState.arr[2][col], 0x02) ^ 
        mult(oldState.arr[3][col],0x03);

        newState.arr[3][col] = mult(oldState.arr[0][col], 0x03) ^ 
        mult(oldState.arr[1][col], 0x01) ^ 
        mult(oldState.arr[2][col], 0x01) ^ 
        mult(oldState.arr[3][col],0x02);
    }

    return newState;
}

State getInitialState(){

    State state;

    for(int i = 0; i < 4; i++)
        for(int j = 0; j < 4; j++){
            state.arr[i][j] = msg[(i) + (j*4)];
        }
    return state;
}

__uint32_t combine(__uint8_t m1,__uint8_t m2,__uint8_t m3,__uint8_t m4){
    
    uint32_t val = 0;

    val = val | (((uint32_t)m1) << 24);
    val = val | (((uint32_t)m2) << 16);
    val = val | (((uint32_t)m3) << 8);
    val = val | (((uint32_t)m4) << 0);
    return val;
}

//y assumed to be <= 15
__uint8_t mult(__uint8_t x, __uint32_t y){
    
    __uint8_t val = 0;
    __uint8_t x1 = xtime(x);
    __uint8_t x2 = xtime(x1);
    __uint8_t x3 = xtime(x2);

    if((y & 0x01) == 0x01) //check if 1s bit is set
        val = val ^ x;
    if((y & 0x02) == 0x02) //check if 2s bit is set
        val = val ^ x1;
    if((y & 0x04)== 0x04) //check if 4s bit is set
        val = val ^ x2;
    if((y & 0x08) == 0x08) //check if 8s bit is set
        val = val ^ x3;

    return val;
}

__uint8_t xtime(uint8_t x){

    uint8_t val = x << 1;

    //check carryout
    if(x >> 7 == 0x01){
        val = val ^ 0x1b;
    }
    return val;
}

 keyExpansion KeyExpansion(){

    keyExpansion expKey;

    __uint32_t arr[11][4];

    for(int i = 0; i < 4; i++){ //K0 <- K
        arr[0][i] = combine(key[4*i], key[(4*i)+1],key[(4*i)+2],key[(4*i)+3]);
    }

    for(int i = 1; i <= 10; i++){ //1 to 10 loop
    
        arr[i][0] = arr[i-1][0] ^ S32(cycShift(arr[i-1][3],8)) ^ C[i];
        arr[i][1] = arr[i-1][1] ^ arr[i][0];  
        arr[i][2] = arr[i-1][2] ^ arr[i][1];
        arr[i][3] = arr[i-1][3] ^ arr[i][2];
    
    }
    
    /*Done for readability and consistency of notation*/
    for(int i = 0; i < 11 ;i++){ //decompose words into chars (word -> 2d arr of chars)
        for(int j = 0; j<4; j++){
            //print rnd key info
            printf("%08x  ", arr[i][j]);

            expKey.arr[i][0][j] = (__uint8_t)(arr[i][j] >> 24);
            expKey.arr[i][1][j] = (__uint8_t)(arr[i][j] >> 16);
            expKey.arr[i][2][j] = (__uint8_t)(arr[i][j] >> 8);
            expKey.arr[i][3][j] = (__uint8_t)(arr[i][j]);
        }
        printf("\n");
    }


    return expKey;
}

__uint32_t S32(__uint32_t input){

    __uint32_t m1 = S(((__uint8_t) input)); //bottom
    __uint32_t m2 = S(((__uint8_t) (input >> 8)));
    __uint32_t m3 = S(((__uint8_t) (input >> 16)));
    __uint32_t m4 = S(((__uint8_t) (input >> 24)));

    __uint32_t val = 0;
    val = (m4 << 24) | (m3 << 16) | (m2 << 8) | (m1);
    return val;

}

__uint8_t S(__uint8_t input){

    __uint8_t y = input & 0x0f;

    __uint8_t x = (input & 0xF0) >> 4;

    return sbox[x][y];
}

__uint8_t invS(__uint8_t input){

    __uint8_t y = input & 0x0f;

    __uint8_t x = (input & 0xF0) >> 4;

    return invsbox[x][y];
}

__uint32_t cycShift(__uint32_t input, int shiftSize){

    return (input << shiftSize) | (input >> (WORD_SIZE - shiftSize));

}

void loadFile(char* arg, __uint8_t mem[]){

    FILE* fileptr = fopen(arg, "r");
    
    char buffer[100];
    fgets(&buffer[0], 100, fileptr);

    char* token = strtok(&buffer[0], " ");
    mem[0] = (__uint8_t)strtol(token, NULL, 16);

    for(int i = 1; i < 16; i++){

        token = strtok(NULL, " ");
        mem[i] = (__uint8_t)strtol(token, NULL, 16);
    }

    fclose(fileptr);

}
