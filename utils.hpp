#ifndef UTILS_H_
#define UTILS_H_
#include <stdio.h>
int is_ascii_symbol(unsigned char c);
int is_ascii(unsigned char c);
size_t file_get_sz(FILE *fd);
#endif