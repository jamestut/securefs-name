#include "platform.h"

#ifdef WIN32
// TODO
#else

#include <termios.h>
#include <unistd.h>

int set_echo(int state)
{
    int prev_state;

    struct termios t;
    tcgetattr(STDIN_FILENO, &t);
    prev_state = (t.c_lflag & ECHO) && 1;
    if(!state)
        t.c_lflag &= ~ECHO;
    else
        t.c_lflag |= ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &t);

    return prev_state;
}

#endif