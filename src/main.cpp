#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <filesystem>
#include <string>

#include "hrtypes.h"
#include "hrcrypto.h"
#include "hrio.h"

#define STRLIT(str) (str), (sizeof(str) - 1)

bool starts_with(const char* haystack, size_t haystack_size, const char* needle, size_t needle_size) {
    if (haystack_size < needle_size) {
        return false;
    }
    for (size_t i = 0; i < needle_size; i += 1) {
        if (haystack[i] != needle[i]) {
            return false;
        }
    }
    return true;
}

bool is_png(const char* data, size_t size) {
    return starts_with(data, size, STRLIT("\x89PNG"));
}

bool is_bmp(const char* data, size_t size) {
    return starts_with(data, size, STRLIT("BM"));;
}

bool is_plain(std::string ext, const char* data, size_t size) {
    if (ext == ".png") {
        return is_png(data, size);
    }
    if (ext == ".bmp") {
        return is_bmp(data, size);
    }
    return true;
} 

void decrypt_file(const std::filesystem::path& rootpath, const std::filesystem::path& outputdir, const std::filesystem::path& path) {
    std::string str = path.generic_string();
    if (str.find("decrypt") != std::string::npos) {
        return;
    }
    std::string ext = path.extension().generic_string();

    auto rel = std::filesystem::relative(path, rootpath);

    auto output_pth = outputdir / rel;
    auto output_path = (output_pth).generic_string();

    size_t encrypted_size = 0;
    char* encrypted = read_file(str.c_str(), &encrypted_size);

    char* decrypted = (char*)malloc(encrypted_size + 1);
    decrypted[encrypted_size] = 0;

    if (!is_plain(ext, encrypted, encrypted_size)) {
        decrypt(encrypted, encrypted_size, decrypted, gDecriptionStateData);
        free(encrypted);
        if (!is_plain(ext, decrypted, encrypted_size)) {
            std::cout << "failed to decode: " << str << "\n";
            if (rootpath == outputdir) {
                printf("skipping\n");
                return;
            }
        }
    } else {
        if (rootpath == outputdir) {
            return;
        }
        decrypted = encrypted;
    }

    std::filesystem::create_directories(output_pth.parent_path());
    FILE* output_file = fopen(output_path.c_str(), "wb");
    if (output_file == nullptr) {
        printf("unable to open file %s\n", output_path.c_str());
        exit(1);
    }
    fwrite(decrypted, 1, encrypted_size, output_file);
    fclose(output_file);
    free(decrypted);
}

void walk_dir(const std::filesystem::path& input, const std::filesystem::path& output, const std::filesystem::path& path) {    
    for (const auto& child: std::filesystem::directory_iterator(path)) {
        if (child.is_directory()) {
            walk_dir(input, output, child.path());
        }
        if (child.is_regular_file()) {
            decrypt_file(input, output, child.path());   
        }
    }
}
void print_help() {
    printf("hv-decrypt <input-directory> [<output-directory>]\n");
}

int main(int argc, char const *argv[]) {
    if (argc < 2) {
        printf("missing argument <input-directory>\n");
        print_help();
        exit(1);
    }
    const char* input_dir = argv[1];
    const char* output_dir = input_dir;
    if (argc > 2) {
        output_dir = argv[2];
    }

    walk_dir(input_dir, output_dir, input_dir);
}


