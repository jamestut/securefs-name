#include "exceptions.hpp"
#include "mystring.h"
#include <cerrno>
#include <cstring>
#include <cstdarg>

ErrnoException::ErrnoException(int errnum) {
    this->errnum = errnum;
}

const char * ErrnoException::what () const throw () {
    return strerror(this->errnum);
}

MessageException::MessageException(const char * fmt ...) {
    va_list args;
    va_start(args, fmt);
    this->msg = securefs::vstrprintf(fmt, args);
    va_end(args);
}

const char * MessageException::what () const throw () {
    return this->msg.c_str();
}