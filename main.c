/* SEAPASS - Basic password manager
 * 2017 - Patrick Withams
 */

#include <stdio.h>
#include <stdlib.h>

char * openFile()
{
    // create and open file
    FILE *fptr;
    fptr = fopen("datafile", "r");
    // seek to end and calculate size
    fseek(fptr, 0, SEEK_END);
    int sz = ftell(fptr);
    // use size to allocate memory to
    // file buffer
    int newsize = (sizeof(char)*sz)+1;
    char * fileBuffer = malloc(newsize);
    // seek back to start and read contents
    // into buffer
    fseek(fptr, 0, SEEK_SET);
    fread(fileBuffer, 1, sz, fptr);
    // set last value to null
    // and close file
    fileBuffer[sz+1] = 0;
    fclose(fptr);
    // return pointer to allocated
    // memory space
    return fileBuffer;
}

char * findPassword(char * contents, int index)
{
    // set default result for errors
    char * password = malloc(sizeof(char)*120);
    password[0] = '!';
    // check if index error signal was provided
    if(index == -1) {
        printf("Site does not exist\n");
        return password;
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
    return password;
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
int searchPassword(char * query)
{
    char * fileContents = openFile();
    int index = searchFileContents(query, fileContents);
    char * password = findPassword(fileContents, index);
    printf("Password: %s\n", password);
    free(password);
    free(fileContents);
    return 0;
}

int processInput(char * input)
{
    input = stripNewLine(input);
    if(input[0] == 'q' && input[1] == 0) {
        printf("Quitting...\n");
        return 0;
    } else {
        searchPassword(input);
    }
    return 1;
}


int main()
{
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
        runProgram = processInput(input);
    }
    return 0;
}
