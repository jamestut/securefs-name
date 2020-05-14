#pragma once

#include "crypto.h"
#include "mystring.h"

#include <map>
#include <memory>
#include <mutex>
#include <string>

#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/secblock.h>

namespace securefs
{
namespace lite
{
    std::string encrypt_path(AES_SIV& encryptor, std::string path);
    std::string decrypt_path(AES_SIV& decryptor, std::string path);
}    // namespace lite
}    // namespace securefs
