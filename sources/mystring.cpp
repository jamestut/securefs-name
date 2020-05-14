#include "mystring.h"
#include "myutils.h"
#include "exceptions.hpp"

#include <utf8proc/utf8proc.h>

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <system_error>

namespace securefs
{
std::string vstrprintf(const char* format, va_list args)
{
    va_list copied_args;
    va_copy(copied_args, args);
    const int MAX_SIZE = 4000;
    char buffer[MAX_SIZE + 1];
    int size = vsnprintf(buffer, sizeof(buffer), format, copied_args);
    va_end(copied_args);
    if (size < 0)
        throw ErrnoException(errno);
    if (size <= MAX_SIZE)
        return std::string(buffer, size);
    std::string result(static_cast<std::string::size_type>(size), '\0');
    vsnprintf(&result[0], size + 1, format, args);
    return result;
}

std::string strprintf(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    DEFER(va_end(args));
    return vstrprintf(format, args);
}

std::string to_lower(const std::string& str)
{
    std::string result = str;
    for (char& c : result)
    {
        if (c >= 'A' && c <= 'Z')
            c += 'a' - 'A';
    }
    return result;
}

void parse_hex(StringRef hex, byte* output, size_t len)
{
    if (hex.size() % 2 != 0)
        throw MessageException("Hex string must have an even length");
    if (hex.size() / 2 != len)
        throw MessageException("Mismatch hex and raw length");

    for (size_t i = 0; i < hex.size(); i += 2, ++output)
    {
        switch (hex[i])
        {
        case '0':
            *output = 0x0;
            break;
        case '1':
            *output = 0x10;
            break;
        case '2':
            *output = 0x20;
            break;
        case '3':
            *output = 0x30;
            break;
        case '4':
            *output = 0x40;
            break;
        case '5':
            *output = 0x50;
            break;
        case '6':
            *output = 0x60;
            break;
        case '7':
            *output = 0x70;
            break;
        case '8':
            *output = 0x80;
            break;
        case '9':
            *output = 0x90;
            break;
        case 'a':
            *output = 0xa0;
            break;
        case 'b':
            *output = 0xb0;
            break;
        case 'c':
            *output = 0xc0;
            break;
        case 'd':
            *output = 0xd0;
            break;
        case 'e':
            *output = 0xe0;
            break;
        case 'f':
            *output = 0xf0;
            break;
        default:
            throw MessageException("Invalid character in hexadecimal string");
        }
        switch (hex[i + 1])
        {
        case '0':
            *output += 0x0;
            break;
        case '1':
            *output += 0x1;
            break;
        case '2':
            *output += 0x2;
            break;
        case '3':
            *output += 0x3;
            break;
        case '4':
            *output += 0x4;
            break;
        case '5':
            *output += 0x5;
            break;
        case '6':
            *output += 0x6;
            break;
        case '7':
            *output += 0x7;
            break;
        case '8':
            *output += 0x8;
            break;
        case '9':
            *output += 0x9;
            break;
        case 'a':
            *output += 0xa;
            break;
        case 'b':
            *output += 0xb;
            break;
        case 'c':
            *output += 0xc;
            break;
        case 'd':
            *output += 0xd;
            break;
        case 'e':
            *output += 0xe;
            break;
        case 'f':
            *output += 0xf;
            break;
        default:
            throw MessageException("Invalid character in hexadecimal string");
        }
    }
}

bool ends_with(const char* str, size_t size, const char* suffix, size_t suffix_len)
{
    return size >= suffix_len && memcmp(str + size - suffix_len, suffix, suffix_len) == 0;
}

bool starts_with(const char* str, size_t size, const char* prefix, size_t prefix_len)
{
    return size >= prefix_len && memcmp(str, prefix, prefix_len) == 0;
}

std::vector<std::string> split(StringRef str_, char separator)
{
    const char* start = str_.begin();
    const char* str = start;
    std::vector<std::string> result;
    result.reserve(15);

    while (*str)
    {
        if (*str == separator)
        {
            if (start < str)
                result.emplace_back(start, str);
            start = str + 1;
        }
        ++str;
    }

    if (start < str)
        result.emplace_back(start, str);
    return result;
}

std::string hexify(const byte* data, size_t length)
{
    const char* table = "0123456789abcdef";
    std::string result;
    result.reserve(length * 2);
    for (size_t i = 0; i < length; ++i)
    {
        result += table[data[i] / 16];
        result += table[data[i] % 16];
    }
    return result;
}

static const char* UPPER_BASE32_ALPHABET = "ABCDEFGHIJKMNPQRSTUVWXYZ23456789";
static const char* LOWER_BASE32_ALPHABET = "abcdefghijkmnpqrstuvwxyz23456789";

static size_t get_alphabet_index(byte b, byte next, size_t i)
{
    switch (i)
    {
    case 0:
        return (b >> 3) & 31u;
    case 1:
        return (b >> 2) & 31u;
    case 2:
        return (b >> 1) & 31u;
    case 3:
        return b & 31u;
    case 4:
        return ((b & 15u) << 1u) | (next >> 7u);
    case 5:
        return ((b & 7u) << 2u) | (next >> 6u);
    case 6:
        return ((b & 3u) << 3u) | (next >> 5u);
    case 7:
        return ((b & 1u) << 4u) | (next >> 4u);
    }
    throw MessageException("Invalid index within byte");
}

void base32_encode(const byte* input, size_t size, std::string& output)
{
    output.clear();
    output.reserve((size * 8 + 4) / 5);

    for (size_t bit_index = 0; bit_index < size * 8; bit_index += 5)
    {
        size_t byte_index = bit_index / 8, index_within_byte = bit_index % 8;
        byte b = input[byte_index];
        byte next = byte_index + 1 < size ? input[byte_index + 1] : 0;

        size_t alphabet_index = get_alphabet_index(b, next, index_within_byte);
        if (alphabet_index >= 32)
            throw std::out_of_range("base32_encode encounters internal error");

        output.push_back(UPPER_BASE32_ALPHABET[alphabet_index]);
    }
}

static std::pair<unsigned, unsigned> get_base32_pair(unsigned group, size_t i)
{
    switch (i)
    {
    case 0:
        return std::make_pair(group << 3u, 0);
    case 1:
        return std::make_pair(group << 2u, 0);
    case 2:
        return std::make_pair(group << 1u, 0);
    case 3:
        return std::make_pair(group, 0);
    case 4:
        return std::make_pair(group >> 1u, (group & 1u) << 7u);
    case 5:
        return std::make_pair(group >> 2u, (group & 3u) << 6u);
    case 6:
        return std::make_pair(group >> 3u, (group & 7u) << 5u);
    case 7:
        return std::make_pair(group >> 4u, (group & 15u) << 4u);
    }
    throw MessageException("Invalid index within byte");
}

void base32_decode(const char* input, size_t size, std::string& output)
{
    output.assign(size * 5 / 8, '\0');
    auto out = (byte*)(output.data());

    for (size_t i = 0; i < size; ++i)
    {
        unsigned group;
        const char* finded = std::strchr(UPPER_BASE32_ALPHABET, input[i]);
        if (finded)
            group = unsigned(finded - UPPER_BASE32_ALPHABET);
        else
        {
            finded = std::strchr(LOWER_BASE32_ALPHABET, input[i]);
            if (finded)
            {
                group = unsigned(finded - LOWER_BASE32_ALPHABET);
            }
            else
            {
                throw MessageException("Cannot decode string with base32");
            }
        }

        size_t bit_index = i * 5;
        size_t byte_index = bit_index / 8, index_within_byte = bit_index % 8;
        auto p = get_base32_pair(group, index_within_byte);
        if (byte_index >= output.size())
            throw std::out_of_range("base32 decode encounters internal error");
        out[byte_index] |= p.first;
        if (byte_index + 1 < output.size())
            out[byte_index + 1] |= p.second;
    }
}

std::string escape_nonprintable(const char* str, size_t size)
{
    std::string result;
    result.reserve(size + size / 16);
    for (size_t i = 0; i < size; ++i)
    {
        char c = str[i];
        if (isprint(static_cast<unsigned char>(c)))
        {
            result.push_back(c);
        }
        else
        {
            char tmp[10];
            snprintf(tmp, sizeof(tmp), "\\x%02x", static_cast<unsigned char>(c));
            result.append(tmp);
        }
    }
    return result;
}

bool is_ascii(StringRef str)
{
    for (char c : str)
    {
        if (static_cast<signed char>(c) < 0)
        {
            return false;
        }
    }
    return true;
}
}    // namespace securefs
