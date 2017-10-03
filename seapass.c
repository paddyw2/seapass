/*
 * SEAPASS - Basic password manager
 * 2017 - Patrick Withams 
 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include "seapass.h"
#include "encryption.h"

#define ENCRYPTEDFILE "cryptofile"
#define SOURCEFILE "datafile.txt"
#define PASSWORDSIZE 256
#define BLOCKSIZE 16
#define DIGESTSIZE 32

/*
 * Custom get input function
 * Reads stdin to chosen buffer, and returns
 * the length of any input overflow
 * Note: Always returns string with a new line
 * at the end to be consistent
 * Errors are detected by a greater than zero
 * return value
 */
int get_user_input(char * buffer, int buffer_size)
{
    int overflow_value = 0;
    char current_char = 0;
    int counter = 0;
    
    // read user input into buffer until
    // either buffer limit is reached, or
    // a new line or EOF is submitted
    while(counter < buffer_size)
    {
        current_char = getchar();
        buffer[counter] = current_char;
        if(current_char == '\n' ||
           current_char == EOF)
            break;
        counter++;
    }

    // if input was larger than buffer size
    // dump remaining contents to variable
    // and record verflow length
    if(counter >= buffer_size) {
        // artificially create new line
        // to keep a standard
        buffer[buffer_size-1] = '\n';
        char dump = getchar();
        overflow_value = 1;
        while(dump != '\n' && dump != EOF) {
            dump = getchar();
            overflow_value++;
        }
    }
    // return overflow length
    return overflow_value;
}

/*
 * Prints help menu
 */
int print_help()
{
    printf("QUIT: q\n"
           "CHANGE PASSWORD FILE: n\n"
           "HELP: h\n");
    return 0;
}

/*
 * Confirms the user wants to recreate password file
 * then deletes encrypted file, and jumps to account
 * setup
 */
int create_new_password_file()
{
    printf("Are you sure you want to delete "
            "your current password file? (Y/n) ");
    // get first input character
    int input_size = 2;
    char user_input[input_size];
    int overflow = get_user_input(user_input, input_size);

    // when input gathered, process it
    if(overflow > 0) {
        printf("Invalid input\n");
    } else if(user_input[0] == '\n' ||
       user_input[0] == 'y' || user_input[0] == 'Y') {
        printf("You answered yes\n");
        // delete password file
        remove(ENCRYPTEDFILE);
        // recreate file
        check_account_exists();
    } else {
        printf("You answered no\n");
        // do nothing
    }

    return 0;
}

/*
 * opens a file in the current directoy by name
 * and returns its contents as an unsigned char *
 */
unsigned char * open_file(char filename[])
{
    // create and open file
    FILE *fptr;
    fptr = fopen(filename, "r");
    if(!fptr) {
        printf("File opening failed\n");
        exit(EXIT_FAILURE);
    }
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
    //BIO_dump_fp (stdout, (const char *)fileBuffer, sz);
    return fileBuffer;
}

/*
 * opens a file and reads its size
 * if the file does not exist, it returns -1
 * otherwise it returns the size
 */
int get_file_size(char filename[])
{
    // create and open file
    FILE *fptr;
    int sz;
    fptr = fopen(filename, "r");
    if(fptr) {
        // seek to end and calculate size
        fseek(fptr, 0, SEEK_END);
        sz = ftell(fptr);
    } else {
        return -1;
    }
    return sz;
}

/*
 * writes the values in fileContents to a file in the
 * current directory specified by the filename
 * if the file does not exist, it will create one
 * if it does exist, it will overwrite it
 */
int write_file(unsigned char * fileContents, int len, char * filename)
{
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

/*
 * Given an index signifying the location of a site, the
 * password is extracted and copied into char * password
 */
int find_password(char * password, char * contents, int index)
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

/*
 * Given a partial or whole site query, this returns
 * the index of the searched site
 * i.e. if 'ace' is searched, it returns the index
 * for 'facebook', presuming it exists
 */
int search_file_contents(char * query, char * contents)
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

/*
 * Given a string input, the new line
 * character is stripped and changed to
 * a NULL character
 */
char * strip_new_line(char * input)
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

/*
 * Manages the sub functions that are required for
 * finding a password given a partial site query
 * Once password is extracted, or the error message,
 * this string is printed
 */
int search_password(char * query, unsigned char * content)
{
    int password_length = 256;
    char * fileContents = (char *) content;
    int index = search_file_contents(query, fileContents);
    char * password = malloc(password_length);
    find_password(password, fileContents, index);
    if(password[0] != '!')
        printf("Password: %s\n", password);
    bzero(password, password_length);
    return 0;
}

/*
 * Given a user input string, this function decides
 * whether to search for a site or quit the program
 */
int process_input(char * input, unsigned char * content)
{
    input = strip_new_line(input);
    if(input[0] == 'q' && input[1] == 0) {
        printf("Quitting\n");
        return 0;
    } else if(input[0] == 'n' && input[1] == 0) {
        create_new_password_file();
    } else if(input[0] == 'h' && input[1] == 0) {
        print_help();

    } else {
        search_password(input, content);
    }
    return 1;
}

/*
 * Takes a 256bit password digest as a parameter and
 * decrypts the contents of the encrypted password file
 * by extracting the IV from the start of the file, and
 * then passing to the OpenSSL example function found
 * in encryption.h
 */
unsigned char * decrypt_password_file(unsigned char *key)
{
    // get size of encrypted file and extract to
    // orig_ciphertext
    int filesize = get_file_size(ENCRYPTEDFILE);
    unsigned char * orig_ciphertext = malloc(filesize);
    orig_ciphertext = open_file(ENCRYPTEDFILE);

    // get size of actual encrypted data by subtracting
    // IV size
    int ciphertext_len = filesize-BLOCKSIZE;
    unsigned char * ciphertext = malloc(ciphertext_len);

    // copy the actual encrypted data to ciphertext
    memcpy(ciphertext, orig_ciphertext+BLOCKSIZE, ciphertext_len);

    // create IV variable and extract first 128bits of file
    // into variable
    unsigned char * iv = malloc(BLOCKSIZE);
    memcpy(iv, (const char *)orig_ciphertext, BLOCKSIZE);

    printf("Decrypting...\n");
    int decryptedtext_len;
    unsigned char * decryptedtext = malloc(ciphertext_len);

    // decrypt using OpenSSL example function
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);

    // Add a NULL terminator. We are expecting printable text
    decryptedtext[decryptedtext_len] = '\0';

    return decryptedtext;
}

/*
 * Encrypts the provided data (plaintext) using the 256bit
 * password digest (key)
 * Generates a random 128bit IV to encrypt with and stores
 * this in plaintext at the start of the encrypted file
 */
int encrypt_password_file(unsigned char *key, unsigned char * plaintext)
{
    // generate random IV
    unsigned char *iv = malloc(BLOCKSIZE);
    if (!RAND_bytes(iv, BLOCKSIZE)) {
        printf("IV generation error");
        exit(EXIT_FAILURE);
    }
    int size = strlen((char *) plaintext);

  // make cipher text buffer 5x plaintext to allow enough space to
  // expand the plaintext into ciphertext
  int ptsize = 5*size;
  unsigned char ciphertext[ptsize];

  int ciphertext_len;

  // initialize the OpenSSL library
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);

  // encrypt the plaintext using the OpenSSL example function 
  ciphertext_len = encrypt (plaintext, size, key, iv, ciphertext);

  printf("Encrypting...\n");

  // create buffer for final file contents
  // that contains IV + ciphertext
  int cipher_iv_len = ciphertext_len+BLOCKSIZE;
  unsigned char * cipher_iv = malloc(cipher_iv_len);

  // copy IV into first 128bits of file buffer
  memcpy(cipher_iv, iv, BLOCKSIZE);
  // copy ciphertext into rest of buffer
  memcpy(cipher_iv+BLOCKSIZE, ciphertext, ciphertext_len);

  // write file buffer to file
  write_file(cipher_iv, cipher_iv_len, ENCRYPTEDFILE);

  return 0;
}

/*
 * Prompts the user for a password
 * Takes input, generates sha256 hash of input
 * Zeroes the original input
 * Updates parameter variable with hash result
 */
int get_password_digest(unsigned char * password_digest)
{
    // prompt user for password
    printf("Enter password: ");
    char next_val;
    char * password = malloc(PASSWORDSIZE);
    bzero(password, PASSWORDSIZE);
    // get user input password, with new line
    get_user_input(password, PASSWORDSIZE);
    // replace new line with NULL
    strip_new_line(password);
    // generate hash of password
    unsigned char digest[DIGESTSIZE];
    get_SHA256((unsigned char *)password, PASSWORDSIZE, digest);
    // zero password data
    bzero(password, PASSWORDSIZE);
    // update parameter pointer
    memcpy(password_digest, digest, DIGESTSIZE);
    return 0;
}

/*
 * Checks if the encrypted password file exists
 * If it does not, then most likely a new user
 * so provide instructions on how to set up a
 * new password file
 */
int check_account_exists()
{
    int filesize = get_file_size(ENCRYPTEDFILE);
    // if password file does not exist
    if(filesize < 1) {
        printf("No account detected\n");
        printf("Looking for datafile.txt...\n");
        filesize = get_file_size(SOURCEFILE);
        // if plaintext file needed for password file
        // setup does not exist
        if(filesize < 1) {
            printf("To create an account, create a datafile.txt\n");
            exit(EXIT_FAILURE);
        } else {
            // if plaintext file with password info does exist
            // prompt user for master password and encrypt file
            printf("Encrypting datafile.txt...\n");
            unsigned char * contents = open_file(SOURCEFILE);
            unsigned char *digest = malloc(DIGESTSIZE);
            // prompt for password
            get_password_digest(digest);
            // encrypt plaintext buffer using password digest
            encrypt_password_file(digest, contents); 
            // indicate process completion
            printf("Encryption complete\n");
            printf("Restart the program to access your account\n");
            exit(EXIT_SUCCESS);
        }
    }
    return 0;
}

/*
 * Contains main loop of program
 */
int main()
{
    // check user has a file
    check_account_exists();

    // get user password
    unsigned char *digest = malloc(DIGESTSIZE);
    get_password_digest(digest);

    // get decrypted file contents
    unsigned char * filecontents = decrypt_password_file(digest);

    // main program loop
    printf("-- Welcome to SeaPass --\n");
    printf("Enter 'h' for help\n");
    int runProgram = 1;
    int input_size = 50;
    while(runProgram == 1) {
        char user_input[input_size];
        printf("Enter site query\n");
        printf("> ");
        // get user input
        get_user_input(user_input, input_size);
        // process user input
        runProgram = process_input(user_input, filecontents);
    }
    // encrypt password file with new IV
    encrypt_password_file(digest, filecontents); 
    // zero plaintext data from memory
    bzero(filecontents, strlen((const char *)filecontents));
    return 0;
}
