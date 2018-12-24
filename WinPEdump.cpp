#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SHARED_LIBS 100
//Get info of a WinPE executable.
//TODO: use a header struct instead of keeping track of offset & size

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

#define IMAGE_BASE_OFF PE_SIG_OFF + 52
#define IMAGE_BASE_SZ 0x4
#define SECTION_ALIGNMENT_OFF PE_SIG_OFF + 56
#define SECTION_ALIGNMENT_SZ 0x4
#define FILE_ALIGNMENT_OFF PE_SIG_OFF + 60
#define FILE_ALIGNMENT_SZ 0x4

#define SECTION_HEADER_RAW_LEN_OFF SECTION_HEADER_NAME + 16
#define SECTION_HEADER_RAW_LEN_SZ 0x4
#define SECTION_HEADER_RAW_LOC_OFF SECTION_HEADER_NAME + 20
#define SECTION_HEADER_RAW_LOC_SZ 0x4
#define SECTION_HEADER_LEN 40


int hex_search(unsigned char *val, int sz, unsigned char *buf, int bufsz)
{
    for (int i = 0; i < bufsz - sizeof(val); i++) {
        if (memcmp(buf + i, val, sz) == 0) {
            return i;
        }
    }
    return -1;
}


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


//Dump memory
//Format: type=0->ascii, type=1->hex
void print_mem(unsigned char *mem, int sz, int type)
{
    for (int i = 0; i < sz; i++) {
        if (type == 1) {
            printf("%02x", mem[i]);
        }
        else {
            if (is_ascii(mem[i])) {
                printf("%c", mem[i]);
            }
            else {
                printf("\\%02x ", mem[i]);
            }
        }
        //if (print_space) printf(" ");
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


int is_big_endian(void)
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


int rewind_till_null(unsigned char *buf, int max)
{
    for (int i = 0; i < max; i++) {
        if (*(buf - i) == '\0') return i;
    }

    return -1;
}


unsigned char *str_find(unsigned char *buf, char *substr, int bufsz)
{
    int sublen = strlen(substr);
    for (int i = 0; i < bufsz - sublen; i++) {
        if (memcmp(buf + i, substr, sublen) == 0) {
            return buf + i;
        }
    }
    return NULL;
}


void print_shared_libs(unsigned char *buf, int max)
{
    char ext[] = ".dll";
    unsigned char *s = buf;
    unsigned char *dll_name = buf;

    for (int i = 0; i < MAX_SHARED_LIBS; i++) {
        if (s > buf + max) break;
        s = str_find(s, ext, max - (s - buf)); //s went too far here
        if (!s) break;

        int dll_len = rewind_till_null(s, s - dll_name + dll_len) - 1; //rewind till null but not before previous dllname
        dll_name = s - dll_len;
        s += dll_len;

        printf("%s\n", dll_name);

    }
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

    printf("\n=Windows specific fields=\n");
    printf("Where file is mapped in memory: "); print_number_at(buf + IMAGE_BASE_OFF, IMAGE_BASE_SZ);
    printf("Where sections should start in memory: "); print_number_at(buf + SECTION_ALIGNMENT_OFF, SECTION_ALIGNMENT_SZ);
    printf("Where sections should start on file: "); print_number_at(buf + FILE_ALIGNMENT_OFF, FILE_ALIGNMENT_SZ);

    printf("\n==Sections\n");
    unsigned short SECTION_HEADER_TABLE_OFF = PE_SIG_OFF + read_mem_at(buf + OPTIONAL_HEADERS_SIZE_OFF, OPTIONAL_HEADERS_SIZE_SZ) + 24; //24=COFF header size + PE_SIG_SZ
    printf("Sections table at 0x%hx\n", SECTION_HEADER_TABLE_OFF);
    short number_of_sections = (short)read_mem_at(buf + NUMBER_OF_SECTIONS_OFF, NUMBER_OF_SECTIONS_SZ);
    int cur_sect_off = 0;
    int SECTION_HEADER_NAME = 0;
    unsigned char *sect_name[16] = {};
    int sect_start[16] = {};
    int sect_sz[16] = {};
    for (size_t i = 0; i < number_of_sections; i++) {
        SECTION_HEADER_NAME = SECTION_HEADER_TABLE_OFF + cur_sect_off;
        print_mem(buf + SECTION_HEADER_NAME, 8, 0);
        sect_name[i] = buf + SECTION_HEADER_NAME;
        sect_start[i] = read_mem_at(buf + SECTION_HEADER_RAW_LOC_OFF, SECTION_HEADER_RAW_LOC_SZ);
        sect_sz[i] = read_mem_at(buf + SECTION_HEADER_RAW_LEN_OFF, SECTION_HEADER_RAW_LEN_SZ);
        printf("- Starts at: "); print_number_at(buf + SECTION_HEADER_RAW_LOC_OFF, SECTION_HEADER_RAW_LOC_SZ);
        printf("- Length: "); print_number_at(buf + SECTION_HEADER_RAW_LEN_OFF, SECTION_HEADER_RAW_LEN_SZ);

        cur_sect_off += SECTION_HEADER_LEN;
    }

    if (argc > 2 && strcmp(argv[2], "-d") == 0) {
        //Dump initialized .data section
        for (int i = 0; i < number_of_sections; i++) {
            if (strstr((const char*)sect_name[i], "data")) {
                printf("\n=Dumping section: %s=\n", sect_name[i]);
                print_mem(buf + sect_start[2], sect_sz[2], 0);
            }
        }

    }

    printf("\n=Shared libraries=\n");
    print_shared_libs(buf + sect_start[1], fsize - sect_start[1]);
    
    //TODO: Add the rest

    free(buf);
    return 0;

}