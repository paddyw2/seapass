/*
 * Prints help menu
 */
int print_help();

/*
 * Confirms the user wants to recreate password file
 * then deletes encrypted file, and jumps to account
 * setup
 */
int create_new_password_file();

/*
 * opens a file in the current directoy by name
 * and returns its contents as an unsigned char *
 */
unsigned char * open_file(char filename[]);

/*
 * opens a file and reads its size
 * if the file does not exist, it returns -1
 * otherwise it returns the size
 */
int get_file_size(char filename[]);

/*
 * writes the values in fileContents to a file in the
 * current directory specified by the filename
 * if the file does not exist, it will create one
 * if it does exist, it will overwrite it
 */
int write_file(unsigned char * fileContents, int len, char * filename);

/*
 * Given an index signifying the location of a site, the
 * password is extracted and copied into char * password
 */
int find_password(char * password, char * contents, int index);

/*
 * Given a partial or whole site query, this returns
 * the index of the searched site
 * i.e. if 'ace' is searched, it returns the index
 * for 'facebook', presuming it exists
 */
int search_file_contents(char * query, char * contents);

/*
 * Given a string input, the new line
 * character is stripped and changed to
 * a NULL character
 */
char * strip_new_line(char * input);

/*
 * Manages the sub functions that are required for
 * finding a password given a partial site query
 * Once password is extracted, or the error message,
 * this string is printed
 */
int search_password(char * query, unsigned char * content);

/*
 * Given a user input string, this function decides
 * whether to search for a site or quit the program
 */
int process_input(char * input, unsigned char * content);

/*
 * Takes a 256bit password digest as a parameter and
 * decrypts the contents of the encrypted password file
 * by extracting the IV from the start of the file, and
 * then passing to the OpenSSL example function found
 * in encryption.h
 */
unsigned char * decrypt_password_file(unsigned char *key);

/*
 * Encrypts the provided data (plaintext) using the 256bit
 * password digest (key)
 * Generates a random 128bit IV to encrypt with and stores
 * this in plaintext at the start of the encrypted file
 */
int encrypt_password_file(unsigned char *key, unsigned char * plaintext);

/*
 * Prompts the user for a password
 * Takes input, generates sha256 hash of input
 * Zeroes the original input
 * Updates parameter variable with hash result
 */
int get_password_digest(unsigned char * password_digest);

/*
 * Checks if the encrypted password file exists
 * If it does not, then most likely a new user
 * so provide instructions on how to set up a
 * new password file
 */
int check_account_exists();
