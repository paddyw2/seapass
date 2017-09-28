/* SEAPASS - Basic password manager
 * 2017 - Patrick Withams */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include "encryption.h"

#define KEYLENGTH 256
#define BLOCKSIZE 16

unsigned char * openFile(char filename[])
{
    // create and open file
    FILE *fptr;
    fptr = fopen(filename, "r");
    // seek to end and calculate size
    fseek(fptr, 0, SEEK_END);
    int sz = ftell(fptr);
    // use size to allocate memory to
    // file buffer
    unsigned char * fileBuffer = malloc(sz);
    // seek back to start and read contents
    // into buffer
    fseek(fptr, 0, SEEK_SET);
    fread(fileBuffer, sizeof(char), sz, fptr);
    // set last value to null
    // and close file
    fileBuffer[sz+1] = 0;
    fclose(fptr);
    // return pointer to allocated
    // memory space
    printf("opening file\n");
    //BIO_dump_fp (stdout, (const char *)fileBuffer, sz);
    return fileBuffer;
}

int writeFile(unsigned char * fileContents, int len, char * filename)
{
    printf("Made it!\n");
    // create and open file
    FILE *fptr;
    fptr = fopen(filename, "w");
    // seek to end and calculate size
    // use size to allocate memory to
    // file buffer
    // seek back to start and read contents
    // into buffer
    fwrite(fileContents, 1, len, fptr);
    // set last value to null
    // and close file
    fclose(fptr);
    // return pointer to allocated
    // memory space
    return 0;
}


int findPassword(char * password, char * contents, int index)
{
    // set default result for errors
    password[0] = '!';
    // check if index error signal was provided
    if(index == -1) {
        printf("Site does not exist\n");
        return 0;
    }

    // first, move to newline to get start of password
    int counter = 0;
    while(contents[index+counter++] != '\n');

    // now extract password
    int pwordindex = 0;
    while(contents[index+counter] != 0) {
        password[pwordindex] = contents[index+counter];
        if(contents[index+counter+1] == '\n') {
            password[pwordindex+1] = 0;
            break;
        }
        counter++;
        pwordindex++;
    }
    return 0;
}

int searchFileContents(char * query, char * contents)
{
    char * password;
    char current = 1;
    int counter = 0;
    int matchFound = 0;
    while(current != 0) {
        current = contents[counter];
        if(current == query[0]) {
            // if initial match found, check rest of string
            int subcounter = 1;
            while(query[subcounter] != 0 && contents[counter + subcounter] != 0) {
                // check if next char valid
                if(query[subcounter] == contents[counter+subcounter])
                    subcounter++;
                else
                    // false alarm, so break, and continue searching
                    break;

                // if end of query reached, success
                if(query[subcounter] == 0)
                    return counter+subcounter;
            }
        }
        counter++;
    }
     
    // failure, no match found
    return -1;
}

char * stripNewLine(char * input)
{
    int counter = 0;
    while(input[counter] != 0)
    {
        if(input[counter] == '\n') {
            input[counter] = 0;
            break;
        }
        counter++;
    }
    return input;
}
int searchPassword(char * query, unsigned char * content)
{
    char * fileContents = (char *) content;
    int index = searchFileContents(query, fileContents);
    char * password = malloc(256);
    findPassword(password, fileContents, index);
    if(password[0] != '!')
        printf("Password: %s\n", password);
    free(password);
    return 0;
}

int processInput(char * input, unsigned char * content)
{
    input = stripNewLine(input);
    if(input[0] == 'q' && input[1] == 0) {
        printf("Quitting\n");
        return 0;
    } else {
        searchPassword(input, content);
    }
    return 1;
}

unsigned char * decrypt_password_file(unsigned char *key)
{
    unsigned char * iv = openFile(".iv");
    unsigned char * ciphertext = malloc(10);
    ciphertext = openFile("cryptofile");
    printf("decrypting...\n");
    int ciphertext_len = strlen((char *) ciphertext);
    int decryptedtext_len;
    unsigned char * decryptedtext = malloc(ciphertext_len);
    //BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);

    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

    //BIO_dump_fp (stdout, (const char *)decryptedtext, decryptedtext_len);
    return decryptedtext;
}

// Not currently used as decrypted file is
// stored in memory and not saved to disk
int encrypt_password_file(unsigned char *key, unsigned char * plaintext)
{
    // generate IV
    unsigned char *iv = malloc(BLOCKSIZE);
    if (!RAND_bytes(iv, BLOCKSIZE)) {
        printf("IV generation error");
        exit(EXIT_FAILURE);
    }
  /* Message to be encrypted */
    int size = strlen((char *) plaintext);


  /* Buffer for ciphertext. Ensure the buffer is long enough for the
   * ciphertext which may be longer than the plaintext, dependant on the
   * algorithm and mode
   */
  // make cipher text buffer 5x plaintext to avoid seg fault
  int ptsize = 5*size;
  unsigned char ciphertext[ptsize];

  int ciphertext_len;

  /* Initialise the library */
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);

  /* Encrypt the plaintext */
  ciphertext_len = encrypt (plaintext, size, key, iv,
                            ciphertext);

  printf("encrypting...\n");
  //BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
  writeFile(ciphertext, ciphertext_len, "cryptofile");
  writeFile(iv, BLOCKSIZE, ".iv");

  return 0;
}

unsigned char * auth()
{
    // prompt user for password
    char next_val;
    unsigned char * password = malloc(KEYLENGTH);
    int counter = 0;
    while(counter < KEYLENGTH) {
        next_val = getchar();
        // detect password entered
        if(next_val == '\n')
            break;
        // continue adding to password
        password[counter] = next_val;
        counter++;
    }
    // null terminate string
    password[counter] = 0;

    return password;
}

int main()
{
    printf("Enter password: ");
    /* A 256 bit key */
    unsigned char *key = auth();
  
    unsigned char * filecontents = malloc(10);
    filecontents = decrypt_password_file(key);

    printf("-- Welcome to SeaPass --\n");
    printf("Enter 'q' to quit\n");
    int runProgram = 1;
    while(runProgram == 1) {
        char userInput[50];
        printf("Enter site query\n");
        printf("> ");
        // get user input
        fgets(userInput, 50, stdin);
        // strip newline character
        char * input = userInput; 
        runProgram = processInput(input, filecontents);
    }
    // zero password data
    //memset(filecontents, 0, strlen((char *)filecontents));
    encrypt_password_file(key, filecontents); 
    return 0;
}
