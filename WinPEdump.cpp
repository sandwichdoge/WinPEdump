#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//Get info of a WinPE executable.

#define BASE 0x0
#define PE_SIG_SZ 0x4
#define MACHINE_OFF PE_SIG_OFF + 0x4
#define MACHINE_SZ 0x2
#define NUMBER_OF_SECTIONS_OFF PE_SIG_OFF + 0x6
#define NUMBER_OF_SECTIONS_SZ 0x2
#define DATETIME_OFF PE_SIG_OFF + 0x8
#define DATETIME_SZ 0x4
#define OPTIONAL_HEADERS_SIZE_OFF PE_SIG_OFF + 20
#define OPTIONAL_HEADERS_SIZE_SZ 0x2

#define FILE_TYPE_OFF PE_SIG_OFF + 24
#define FILE_TYPE_SZ 0x2
#define CODE_SIZE_OFF PE_SIG_OFF + 28
#define CODE_SIZE_SZ 0x4
#define INITIALIZED_DATA_OFF PE_SIG_OFF + 32
#define INITIALIZED_DATA_SZ 0x4
#define UNINITIALIZED_DATA_OFF PE_SIG_OFF + 36
#define UNINITIALIZED_DATA_SZ 0x4
#define PROGRAM_ENTRY_POINT_OFF PE_SIG_OFF + 40
#define PROGRAM_ENTRY_POINT_SZ 0x4
#define BASE_OF_CODE_OFF PE_SIG_OFF + 44
#define BASE_OF_CODE_SZ 0x4
#define BASE_OF_DATA_OFF PE_SIG_OFF + 48
#define BASE_OF_DATA_SZ 0x4


int hex_search(unsigned char *val, int sz, unsigned char *buf, int bufsz)
{
    for (int i = 0; i < bufsz - sizeof(val); i++) {
        if (memcmp(buf + i, val, sz) == 0) {
            return i;
        }
    }
    return -1;
}


void print_mem(unsigned char *mem, int sz)
{
    for (int i = 0; i < sz; i++) {
        printf("%02x ", mem[i]);
        if (i >= 16 && i % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

void swap(unsigned char *a, unsigned char *b)
{
    unsigned char c = *a;
    *a = *b;
    *b = c;
}

void mem_reverse(unsigned char *mem, int sz)
{
    int real_len = sz;
    for (; real_len > 0 && mem[real_len-1] == 0; real_len--) {
    }
    for (int i = 0; i < real_len / 2; i++) {
        swap(&mem[i], &mem[real_len - 1 - i]);
    }
}


bool is_big_endian(void)
{
    union {
        unsigned int i;
        char c[4];
    } bint = {0x01020304};

    return bint.c[0] == 1; 
}


//Flip high byte-order to low byte-order
void encode(unsigned char *mem, int sz)
{
    if (!is_big_endian()) {
        mem_reverse(mem, sz);
    }
}


size_t conv_mem_to_real_offset(unsigned char *mem, int sz)
{
    size_t ret = 0;
    if (sz > sizeof(size_t)) return -1; //too big
    unsigned char tmp[sizeof(size_t)];
    memcpy(tmp, mem, sz);
    ret = *(size_t*)tmp;
    return ret;
}


int print_real_offset(unsigned char *mem, int sz)
{
    if (sz > sizeof(size_t)) {
        printf("Invalid mem size.\n");
        return -1; //too big
    }
    size_t real_offset = conv_mem_to_real_offset(mem, sz);
    printf("0x%hx\n", real_offset);

    return 0;
}


int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: %s <program_name.exe>\n", argv[0]);
        return -1;
    }
    
    FILE *fd = fopen(argv[1], "rb");
    unsigned char buf[1024 * 120] = {};

    fread(buf, 1, sizeof(buf), fd);

    for (int i = 0; i < sizeof(buf); i++) {
        //printf(" 0x%hx", buf[i]); //Hexdump program data
    }

    unsigned char tmp[128] = {};
    
    unsigned int constant_sig = 0x4d5a;
    memcpy(tmp, &constant_sig, 2);
    encode(tmp, 2);
    printf("Constant signature at: %d\n", hex_search(tmp, 2, buf, sizeof(buf)));

    unsigned int PE_sig = 0x00004550; //WinPE signature
    memcpy(tmp, &PE_sig, 4); //Size of WinPE Signature is 4

    int PE_SIG_OFF = hex_search(tmp, 4, buf, sizeof(buf));
    printf("PE signature at: 0x%hx\n", PE_SIG_OFF);

    printf("\n=COFF headers=\n");
    printf("Machine signature: "); print_real_offset(buf + MACHINE_OFF, MACHINE_SZ);
    printf("Number of sections: "); print_real_offset(buf + NUMBER_OF_SECTIONS_OFF, NUMBER_OF_SECTIONS_SZ);
    printf("Datetime stamp: "); print_real_offset(buf + DATETIME_OFF, DATETIME_SZ);
    printf("Optional headers size: "); print_real_offset(buf + OPTIONAL_HEADERS_SIZE_OFF, OPTIONAL_HEADERS_SIZE_SZ);

    printf("\n=Standard fields=\n");
    printf("File type signature: "); print_real_offset(buf + FILE_TYPE_OFF, FILE_TYPE_SZ);
    printf("Code section size: "); print_real_offset(buf + CODE_SIZE_OFF, CODE_SIZE_SZ);
    printf("Initialized data size: "); print_real_offset(buf + INITIALIZED_DATA_OFF, INITIALIZED_DATA_SZ);
    printf("Uninitialized data size: "); print_real_offset(buf + UNINITIALIZED_DATA_OFF, UNINITIALIZED_DATA_SZ);
    printf("Program starts at: "); print_real_offset(buf + PROGRAM_ENTRY_POINT_OFF, PROGRAM_ENTRY_POINT_SZ); //address in mem
    printf("Base of code section: "); print_real_offset(buf + BASE_OF_CODE_OFF, BASE_OF_CODE_SZ);
    printf("Base of .data section: "); print_real_offset(buf + BASE_OF_DATA_OFF, BASE_OF_DATA_SZ);

    //TODO: Add the rest
    return 0;
}