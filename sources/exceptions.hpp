#pragma once

#include <exception>
#include <string>
#include <cstdarg>

class ErrnoException : public std::exception {
public:
   ErrnoException(int errnum);
   const char * what () const throw ();
private:
   int errnum;
};

class MessageException : public std::exception {
public:
   MessageException(const char * fmt ...);
   const char * what () const throw ();
private:
   std::string msg;
};