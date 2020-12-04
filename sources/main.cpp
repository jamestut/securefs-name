#include "exceptions.hpp"
#include "crypto.h"
#include "lite_fs.h"
#include "platform.h"

#include <cstdio>
#include <cstdlib>
#include <configparser.hpp>
#include <exception>
#include <bsd/readpassphrase.h>

#define PASSPHRASE_LENGTH 256

using namespace securefs;
using namespace securefsname;

const char * readline(bool echo, const char * prompt, size_t* rd)
{
    thread_local static size_t linesize = 1024;
    thread_local static char * line;

    if(prompt && *prompt) 
    {
        fputs(prompt, stderr);
        fflush(stderr);
    }

    int prev_echo_status;
    if(!echo)
        prev_echo_status = set_echo(0);

    ssize_t lrd = getline(&line, &linesize, stdin);

    if(!echo)
    {
        prev_echo_status = set_echo(prev_echo_status);
        putchar('\n');
    }

    if(lrd < 0)
        return nullptr;
    if(line[lrd-1] == '\n')
        line[--lrd] = 0;

    if(rd)
        *rd = lrd;

    return line;
}

int main(int argc, char ** argv) {
    if(argc != 3)
    {
        puts("Usage: securefsname (e/d) <securefs.json file>");
        puts("This version only supports version 4 lite of securefs.");
        return 0;
    }

    bool encrypt;
    if(*argv[1] == 'e') 
    {
        encrypt = true;
    } else if(*argv[1] == 'd') 
    {
        encrypt = false;
    } else 
    {
        puts("Invalid mode. Expecting 'e' or 'd'.");
        return 0;
    }
    
    size_t rd;
    char password[PASSPHRASE_LENGTH];
    if(!readpassphrase("Password: ", password, sizeof(password), 0))
    {
        fputs("Error reading password.\n", stderr);
        return 1;
    }
    rd = strlen(password);

    ConfigParseResult config;
    read_config(argv[2], (void*)password, rd, config);
    key_type name_key = get_name_key(config.master_key);
    AES_SIV name_cryptor(name_key.data(), name_key.size());

    fprintf(stderr, "Enter file/folder name to be %s, separated by newline.\n",
        encrypt ? "encrypted" : "decrypted");
    const char * line;
    const auto edfn = encrypt ? lite::encrypt_path : lite::decrypt_path;
    while((line = readline(true, nullptr, &rd)))
    {
        try
        {
            puts(edfn(name_cryptor, line).c_str());
        }
        catch(const std::exception& e)
        {
            printf("(Error: %s)\n", e.what());
        }
    }
    return 0;
}