#pragma once
#include <stdio.h>
#include <stdlib.h>    

char* read_file(const char* path, size_t* sizePtr) {
    FILE* file = fopen(path, "rb");
    if (file == nullptr) {
        printf("unable to open file %s\n", path);
        exit(1);
    }
    fseek(file, 0l, SEEK_END);
    size_t size = ftell(file);
    if (sizePtr != nullptr) {
        *sizePtr = size;
    }
    rewind(file);
    char* output = (char*)malloc(size + 1);
    if (output == nullptr) {
        printf("unable to allocate memory %zd\n", size+1);
        exit(1);
    }
    size_t read = fread(output, 1, size, file);
    if (read != size) {
        printf("failed to read file %zd\n", read);
        exit(1);
    }
    fclose(file);
    output[size] = 0;
    return output;
}

bool write_file(const char* path, const void* data, size_t size) {
    FILE* output_file = fopen(path, "wb");
    if (output_file == nullptr) {
        printf("unable to open file %s\n", path);
        exit(1);
    }
    size_t written = fwrite(data, 1, size, output_file);
    fclose(output_file);
    return true;
}