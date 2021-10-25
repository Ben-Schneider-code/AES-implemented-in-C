# AES-implemented-in-C  
  
aes.c contains routines for encrpyting and decrypting the files passed as parameter, encrypts 1 block at a time  
although it could trivially be modified for arb length inputs.  
Makefile will generate the executable.  

Supply the encryption input as files (formatted correctly like example files) and have fun!  
A test vector has been included as example.  

Run with:

aes test1plaintext.txt test1key.text  
  
The program prints outputs throughout the whole encryption and decryption process for the user to follow along with. 


