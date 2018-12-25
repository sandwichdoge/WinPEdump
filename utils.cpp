#include "utils.hpp"


int is_ascii_symbol(unsigned char c)
{
    static unsigned char symbols[] = {'+', '-', '*', '/', '.', '_', '[', ']', '(', ')', '~', ' '};
    for (int i = 0; i < sizeof(symbols); i++) {
        if (symbols[i] == c) return 1;
    }

    return 0;
}


int is_ascii(unsigned char c)
{
    return (c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || is_ascii_symbol(c));
}


//Get size of already open file
size_t file_get_sz(FILE *fd)
{
    long ret = 0;
    long old = ftell(fd);
    fseek(fd, 0L, SEEK_END);
    ret = ftell(fd);
    fseek(fd, old, SEEK_SET);
    return ret;
}