#include "configparser.hpp"
#include "mystring.h"
#include "crypto.h"
#include <json/json.h>
#include <cryptopp/cpu.h>
#include <cryptopp/hmac.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/rng.h>
#include <cryptopp/sha.h>
#include "exceptions.hpp"

using namespace securefs;
using namespace std;

namespace securefsname 
{
const char* const PBKDF_ALGO_PKCS5 = "pkcs5-pbkdf2-hmac-sha256";
const size_t CONFIG_IV_LENGTH = 32, CONFIG_MAC_LENGTH = 16;
const char* const PBKDF_ALGO_SCRYPT = "scrypt";
const char* const EMPTY_PASSWORD_WHEN_KEY_FILE_IS_USED = " ";
constexpr uint32_t KEY_LENGTH = 32;

const char* get_version_header(unsigned version)
{
    switch (version)
    {
    case 4:
        return "version=4";
    default:
        throw MessageException("Unknown format version");
    }
}

void maybe_derive_with_keyfile(const securefs::key_type& password_dervied_key,
                               StringRef maybe_key_file_path,
                               securefs::key_type& out_key)
{
    if (maybe_key_file_path.empty())
    {
        out_key = password_dervied_key;
        return;
    }
    FILE* filehdl = fopen(maybe_key_file_path.c_str(), "r");
    if(!filehdl)
        throw ErrnoException(errno);
    byte buffer[4096];
    CryptoPP::HMAC<CryptoPP::SHA256> hmac(password_dervied_key.data(), password_dervied_key.size());
    while (true)
    {
        auto sz = fread(buffer, 1, sizeof(buffer), filehdl);
        if (sz <= 0)
        {
            fclose(filehdl);
            break;
        }
        hmac.Update(buffer, sz);
    }
    hmac.TruncatedFinal(out_key.data(), out_key.size());
}

bool parse_config(const Json::Value& config,
                  StringRef maybe_key_file_path,
                  const void* password,
                  size_t pass_len,
                  CryptoPP::AlignedSecByteBlock& master_key,
                  unsigned& block_size,
                  unsigned& iv_size)
{
    unsigned version = config["version"].asUInt();
    if (version == 4)
    {
        block_size = config["block_size"].asUInt();
        iv_size = config["iv_size"].asUInt();
    }
    else
    {
        throw MessageException("Unsupported version %u", version);
    }

    unsigned iterations = config["iterations"].asUInt();

    byte iv[CONFIG_IV_LENGTH];
    byte mac[CONFIG_MAC_LENGTH];
    key_type salt, password_derived_key;
    CryptoPP::AlignedSecByteBlock encrypted_key;

    std::string salt_hex = config["salt"].asString();
    const auto& encrypted_key_json_value = config["encrypted_key"];
    std::string iv_hex = encrypted_key_json_value["IV"].asString();
    std::string mac_hex = encrypted_key_json_value["MAC"].asString();
    std::string ekey_hex = encrypted_key_json_value["key"].asString();

    parse_hex(salt_hex, salt.data(), salt.size());
    parse_hex(iv_hex, iv, array_length(iv));
    parse_hex(mac_hex, mac, array_length(mac));

    encrypted_key.resize(ekey_hex.size() / 2);
    parse_hex(ekey_hex, encrypted_key.data(), encrypted_key.size());
    master_key.resize(encrypted_key.size());

    std::string pbkdf_algorithm = config.get("pbkdf", PBKDF_ALGO_PKCS5).asString();

    if (pbkdf_algorithm == PBKDF_ALGO_PKCS5)
    {
        pbkdf_hmac_sha256(password,
                          pass_len,
                          salt.data(),
                          salt.size(),
                          iterations,
                          0,
                          password_derived_key.data(),
                          password_derived_key.size());
    }
    else if (pbkdf_algorithm == PBKDF_ALGO_SCRYPT)
    {
        auto r = config["scrypt_r"].asUInt();
        auto p = config["scrypt_p"].asUInt();
        libscrypt_scrypt(static_cast<const byte*>(password),
                         pass_len,
                         salt.data(),
                         salt.size(),
                         iterations,
                         r,
                         p,
                         password_derived_key.data(),
                         password_derived_key.size());
    }
    else
    {
        throw MessageException("Unknown pbkdf algorithm %s", pbkdf_algorithm);
    }

    securefs::key_type wrapping_key;
    maybe_derive_with_keyfile(password_derived_key, maybe_key_file_path, wrapping_key);
    CryptoPP::GCM<CryptoPP::AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(wrapping_key.data(), wrapping_key.size(), iv, array_length(iv));
    return decryptor.DecryptAndVerify(master_key.data(),
                                      mac,
                                      array_length(mac),
                                      iv,
                                      array_length(iv),
                                      reinterpret_cast<const byte*>(get_version_header(version)),
                                      strlen(get_version_header(version)),
                                      encrypted_key.data(),
                                      encrypted_key.size());
}

std::unique_ptr<Json::CharReader> create_json_reader()
{
    Json::CharReaderBuilder builder;
    builder["rejectDupKeys"] = true;
    return std::unique_ptr<Json::CharReader>(builder.newCharReader());
}

void read_config(StringRef config_file, void* password, size_t passlen, 
                 ConfigParseResult& result)
{
    FILE* cfgfilehdl = fopen(config_file.c_str(), "r");
    if(!cfgfilehdl)
        throw ErrnoException(errno);

    std::vector<char> str;
    str.reserve(4000);
    while (true)
    {
        char buffer[4000];
        auto sz = fread(buffer, 1, sizeof(buffer), cfgfilehdl);
        if (sz <= 0)
            break;
        str.insert(str.end(), buffer, buffer + sz);
    }
    fclose(cfgfilehdl);

    Json::Value value;
    std::string error_message;
    if (!create_json_reader()->parse(str.data(), str.data() + str.size(), &value, &error_message))
        throw MessageException("Failure to parse the config file: %s", error_message.c_str());

    if(!parse_config(value, "", password, passlen, 
        result.master_key, result.block_size, result.iv_size))
            throw MessageException("Invalid password");
}

key_type get_name_key(CryptoPP::AlignedSecByteBlock& master_key)
{
    key_type name_key;
    if (master_key.size() != 3 * KEY_LENGTH)
        throw MessageException("Master key has wrong length");

    memcpy(name_key.data(), master_key.data(), KEY_LENGTH);
    return name_key;
}

} // namespace securefsname