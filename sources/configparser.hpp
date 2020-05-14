#pragma once

#include "myutils.h"

namespace securefsname
{
    struct ConfigParseResult
    {
        CryptoPP::AlignedSecByteBlock master_key;
        unsigned block_size;
        unsigned iv_size;
    };

    void read_config(securefs::StringRef config_file, void* password, size_t passlen, 
                 ConfigParseResult& result);
    securefs::key_type get_name_key(CryptoPP::AlignedSecByteBlock& master_key);
} // namespace securefsname