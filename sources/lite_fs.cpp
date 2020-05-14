#include "lite_fs.h"
#include "exceptions.hpp"

#include <cryptopp/base32.h>

#include <cerrno>
#include <mutex>

namespace securefs
{
namespace lite
{
    std::string encrypt_path(AES_SIV& encryptor, std::string path)
    {
        byte buffer[2032];
        std::string result;
        result.reserve((path.size() * 8 + 4) / 5);
        size_t last_nonseparator_index = 0;
        std::string encoded_part;

        for (size_t i = 0; i <= path.size(); ++i)
        {
            if (i >= path.size() || path[i] == '/')
            {
                if (i > last_nonseparator_index)
                {
                    const char* slice = path.data() + last_nonseparator_index;
                    size_t slice_size = i - last_nonseparator_index;
                    if (slice_size > 2000)
                        throw ErrnoException(ENAMETOOLONG);
                    encryptor.encrypt_and_authenticate(
                        slice, slice_size, nullptr, 0, buffer + AES_SIV::IV_SIZE, buffer);
                    base32_encode(buffer, slice_size + AES_SIV::IV_SIZE, encoded_part);
                    result.append(encoded_part);
                }
                if (i < path.size())
                    result.push_back('/');
                last_nonseparator_index = i + 1;
            }
        }
        return result;
    }

    std::string decrypt_path(AES_SIV& decryptor, std::string path)
    {
        byte string_buffer[2032];
        std::string result, decoded_part;
        result.reserve(path.size() * 5 / 8 + 10);
        size_t last_nonseparator_index = 0;

        for (size_t i = 0; i <= path.size(); ++i)
        {
            if (i >= path.size() || path[i] == '/')
            {
                if (i > last_nonseparator_index)
                {
                    const char* slice = path.data() + last_nonseparator_index;
                    size_t slice_size = i - last_nonseparator_index;

                    base32_decode(slice, slice_size, decoded_part);
                    if (decoded_part.size() >= sizeof(string_buffer))
                        throw ErrnoException(ENAMETOOLONG);
                    else if (decoded_part.size() <= AES_SIV::IV_SIZE)
                        throw MessageException("Name too short");

                    bool success
                        = decryptor.decrypt_and_verify(&decoded_part[AES_SIV::IV_SIZE],
                                                       decoded_part.size() - AES_SIV::IV_SIZE,
                                                       nullptr,
                                                       0,
                                                       string_buffer,
                                                       &decoded_part[0]);
                    if (!success)
                        throw ErrnoException(EINVAL); // invalid file name
                    result.append((const char*)string_buffer,
                                  decoded_part.size() - AES_SIV::IV_SIZE);
                }
                if (i < path.size())
                    result.push_back('/');
                last_nonseparator_index = i + 1;
            }
        }
        return result;
    }
}    // namespace lite
}    // namespace securefs
