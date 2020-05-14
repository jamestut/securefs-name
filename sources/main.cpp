#include "exceptions.hpp"
#include "crypto.h"
#include "lite_fs.h"
#include "platform.h"

#include <cstdio>
#include <cstdlib>
#include <configparser.hpp>
#include <exception>

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
    if(argc != 2)
    {
        puts("Usage: securefsname <securefs.json file>");
        puts("This version only supports version 4 lite of securefs.");
        return 0;
    }
    
    size_t rd;
    const char * password = readline(false, "Password: ", &rd);
    if(!password)
    {
        fputs("Error reading password.\n", stderr);
        return 1;
    }

    ConfigParseResult config;
    read_config(argv[1], (void*)password, rd, config);
    key_type name_key = get_name_key(config.master_key);
    AES_SIV name_cryptor(name_key.data(), name_key.size());

    fputs("Enter file/folder name to be decrypted, separated by newline.\n",
        stderr);
    const char * line;
    while((line = readline(true, nullptr, &rd)))
    {
        try
        {
            puts(lite::decrypt_path(name_cryptor, line).c_str());
        }
        catch(const std::exception& e)
        {
            printf("(Error: %s)\n", e.what());
        }
    }
    return 0;
}