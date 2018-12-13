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


//Dump memory
//Format: type=0->ascii, type=1->hex
void print_mem(unsigned char *mem, int sz, int type = 1)
{
    for (int i = 0; i < sz; i++) {
        if (type == 1) {
            printf("%02x ", mem[i]);
        }
        else {
            printf("%c ", mem[i]);
        }
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


size_t read_mem_at(unsigned char *mem, int sz)
{
    size_t ret = 0;
    if (sz > sizeof(size_t)) return 0; //too big
    ret = *(size_t*)mem;
    return ret;
}


//Print value at mem address
int print_number_at(unsigned char *mem, int sz)
{
    if (sz > sizeof(size_t)) {
        printf("Invalid mem size.\n");
        return -1; //too big
    }
    size_t real_offset = read_mem_at(mem, sz);
    printf("0x%hx\n", real_offset);

    return 0;
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


int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: %s <program_name.exe> [-d]\n", argv[0]);
        return -1;
    }
    
    FILE *fd = fopen(argv[1], "rb");
    if (!fd) {
        printf("Cannot open target file.\n");
        return -1;
    }

    size_t fsize = file_get_sz(fd);
    unsigned char *buf = (unsigned char*)malloc(fsize);
    fread(buf, 1, fsize, fd);
    fclose(fd);
    
    unsigned char tmp[8] = {};
    
    unsigned int MZ_sig = 0x4d5a; //Constant MZ signature
    memcpy(tmp, &MZ_sig, 2);
    encode(tmp, 2);

    int MZ_sig_pos = hex_search(tmp, 2, buf, fsize);
    if (MZ_sig_pos < 0) {
        printf("Invalid file type.\n");
        free(buf);
        return -1;
    }

    unsigned int PE_sig = 0x00004550; //WinPE signature
    memcpy(tmp, &PE_sig, PE_SIG_SZ); //Size of WinPE Signature is 4

    int PE_SIG_OFF = hex_search(tmp, PE_SIG_SZ, buf, fsize);
    if (PE_SIG_OFF < 0) {
        printf("File is not WinPE type.\n");
        return -1;
    }
    printf("PE signature at: 0x%hx\n", PE_SIG_OFF);

    printf("\n=COFF headers=\n");
    printf("Machine signature: "); print_number_at(buf + MACHINE_OFF, MACHINE_SZ);
    printf("Number of sections: "); print_number_at(buf + NUMBER_OF_SECTIONS_OFF, NUMBER_OF_SECTIONS_SZ);
    printf("Datetime stamp: "); print_number_at(buf + DATETIME_OFF, DATETIME_SZ);
    printf("Optional headers size: "); print_number_at(buf + OPTIONAL_HEADERS_SIZE_OFF, OPTIONAL_HEADERS_SIZE_SZ);

    printf("\n=Standard fields=\n");
    printf("File type signature: "); print_number_at(buf + FILE_TYPE_OFF, FILE_TYPE_SZ);
    printf("Code section size: "); print_number_at(buf + CODE_SIZE_OFF, CODE_SIZE_SZ);
    printf("Initialized data size: "); print_number_at(buf + INITIALIZED_DATA_OFF, INITIALIZED_DATA_SZ);
    printf("Uninitialized data size: "); print_number_at(buf + UNINITIALIZED_DATA_OFF, UNINITIALIZED_DATA_SZ);
    printf("Program starts at: "); print_number_at(buf + PROGRAM_ENTRY_POINT_OFF, PROGRAM_ENTRY_POINT_SZ); //address in mem
    printf("Base of code section: "); print_number_at(buf + BASE_OF_CODE_OFF, BASE_OF_CODE_SZ);
    printf("Base of .data section: "); print_number_at(buf + BASE_OF_DATA_OFF, BASE_OF_DATA_SZ);

    if (strcmp(argv[2], "-d") == 0) {
        //Dump initialized .data section
        size_t init_data_size = read_mem_at(buf + INITIALIZED_DATA_OFF, INITIALIZED_DATA_SZ);
        print_mem(buf + INITIALIZED_DATA_OFF, init_data_size, 0);
    }

    //TODO: Add the rest

    free(buf);
    return 0;

}