#include <stdlib.h>
#include <stdio.h>
#include <iostream>
// #include <fstream>
#include <filesystem>
#include <string>


#include "table.h"

typedef unsigned int uint;


struct astruct_16 {
        char unknown_1[256];
        uint table[64];
        uint unknown_2;
        uint current_decrypt_state;
        char iteration_determinant;
};

uint* DecryptionTable = (uint*)decryption_table_data;


uint decrypt_10(uint *input,uint *output,astruct_16 *decrypt_state)
{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint out_0;
  uint out_1;
  uint out_2;
  uint out_3;
  uint *small_state;
  
  small_state = decrypt_state->table + decrypt_state->current_decrypt_state * 4;
  if ((decrypt_state->iteration_determinant & 2) == 0) {
    printf("unexpected");
    exit(1);
    return (uint)((size_t)small_state & 0xffff0000);
  }
  if ((decrypt_state->iteration_determinant & 2) == 0) {
    printf("unexpected");
        exit(1);
//     iterate_decrypt_state((uint *)decrypt_state);
//     decrypt_state->iteration_determinant = decrypt_state->iteration_determinant ^ 3;
  }
  out_0 = input[0] ^ small_state[0];
  out_1 = input[1] ^ small_state[1];
  out_2 = input[2] ^ small_state[2];
  out_3 = input[3] ^ small_state[3];
  uVar1 = decrypt_state->current_decrypt_state;
  if (uVar1 != 10) {
    if (uVar1 != 0xc) {
      if (uVar1 != 0xe) goto finalization;
      uVar2 = decrypt_state->table[0x34] ^
              DecryptionTable[(out_0 >> 0x18) + 0x800] ^
              DecryptionTable[(out_3 >> 0x10 & 0xff) + 0x900] ^
              DecryptionTable[(out_2 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(out_1 & 0xff) + 0xb00]
      ;
      uVar1 = decrypt_state->table[0x35] ^
              DecryptionTable[(out_1 >> 0x18) + 0x800] ^
              DecryptionTable[(out_0 >> 0x10 & 0xff) + 0x900] ^
              DecryptionTable[(out_3 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(out_2 & 0xff) + 0xb00]
      ;
      uVar5 = decrypt_state->table[0x36] ^
              DecryptionTable[(out_2 >> 0x18) + 0x800] ^
              DecryptionTable[(out_1 >> 0x10 & 0xff) + 0x900] ^
              DecryptionTable[(out_0 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(out_3 & 0xff) + 0xb00]
      ;
      uVar3 = decrypt_state->table[0x37] ^
              DecryptionTable[(out_3 >> 0x18) + 0x800] ^
              DecryptionTable[(out_2 >> 0x10 & 0xff) + 0x900] ^
              DecryptionTable[(out_1 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(out_0 & 0xff) + 0xb00]
      ;
      out_0 = decrypt_state->table[0x30] ^
              DecryptionTable[(uVar2 >> 0x18) + 0x800] ^
              DecryptionTable[(uVar3 >> 0x10 & 0xff) + 0x900] ^
              DecryptionTable[(uVar5 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar1 & 0xff) + 0xb00]
      ;
      out_1 = decrypt_state->table[0x31] ^
              DecryptionTable[(uVar1 >> 0x18) + 0x800] ^
              DecryptionTable[(uVar2 >> 0x10 & 0xff) + 0x900] ^
              DecryptionTable[(uVar3 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar5 & 0xff) + 0xb00]
      ;
      out_2 = decrypt_state->table[0x32] ^
              DecryptionTable[(uVar5 >> 0x18) + 0x800] ^
              DecryptionTable[(uVar1 >> 0x10 & 0xff) + 0x900] ^
              DecryptionTable[(uVar2 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar3 & 0xff) + 0xb00]
      ;
      out_3 = decrypt_state->table[0x33] ^
              DecryptionTable[(uVar3 >> 0x18) + 0x800] ^
              DecryptionTable[(uVar5 >> 0x10 & 0xff) + 0x900] ^
              DecryptionTable[(uVar1 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar2 & 0xff) + 0xb00]
      ;
    }
    uVar3 = decrypt_state->table[0x2c] ^
            DecryptionTable[(out_0 >> 0x18) + 0x800] ^
            DecryptionTable[(out_3 >> 0x10 & 0xff) + 0x900] ^
            DecryptionTable[(out_2 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(out_1 & 0xff) + 0xb00];
    uVar2 = decrypt_state->table[0x2d] ^
            DecryptionTable[(out_1 >> 0x18) + 0x800] ^
            DecryptionTable[(out_0 >> 0x10 & 0xff) + 0x900] ^
            DecryptionTable[(out_3 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(out_2 & 0xff) + 0xb00];
    uVar1 = decrypt_state->table[0x2e] ^
            DecryptionTable[(out_2 >> 0x18) + 0x800] ^
            DecryptionTable[(out_1 >> 0x10 & 0xff) + 0x900] ^
            DecryptionTable[(out_0 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(out_3 & 0xff) + 0xb00];
    uVar5 = decrypt_state->table[0x2f] ^
            DecryptionTable[(out_3 >> 0x18) + 0x800] ^
            DecryptionTable[(out_2 >> 0x10 & 0xff) + 0x900] ^
            DecryptionTable[(out_1 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(out_0 & 0xff) + 0xb00];
    out_0 = decrypt_state->table[0x28] ^
            DecryptionTable[(uVar3 >> 0x18) + 0x800] ^
            DecryptionTable[(uVar5 >> 0x10 & 0xff) + 0x900] ^
            DecryptionTable[(uVar1 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar2 & 0xff) + 0xb00];
    out_1 = decrypt_state->table[0x29] ^
            DecryptionTable[(uVar2 >> 0x18) + 0x800] ^
            DecryptionTable[(uVar3 >> 0x10 & 0xff) + 0x900] ^
            DecryptionTable[(uVar5 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar1 & 0xff) + 0xb00];
    out_2 = decrypt_state->table[0x2a] ^
            DecryptionTable[(uVar1 >> 0x18) + 0x800] ^
            DecryptionTable[(uVar2 >> 0x10 & 0xff) + 0x900] ^
            DecryptionTable[(uVar3 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar5 & 0xff) + 0xb00];
    out_3 = decrypt_state->table[0x2b] ^
            DecryptionTable[(uVar5 >> 0x18) + 0x800] ^
            DecryptionTable[(uVar1 >> 0x10 & 0xff) + 0x900] ^
            DecryptionTable[(uVar2 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar3 & 0xff) + 0xb00];
  }
  uVar1 = decrypt_state->table[0x24] ^
          DecryptionTable[(out_0 >> 0x18) + 0x800] ^ DecryptionTable[(out_3 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(out_2 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(out_1 & 0xff) + 0xb00];
  uVar6 = decrypt_state->table[0x25] ^
          DecryptionTable[(out_1 >> 0x18) + 0x800] ^ DecryptionTable[(out_0 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(out_3 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(out_2 & 0xff) + 0xb00];
  uVar5 = decrypt_state->table[0x26] ^
          DecryptionTable[(out_2 >> 0x18) + 0x800] ^ DecryptionTable[(out_1 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(out_0 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(out_3 & 0xff) + 0xb00];
  uVar2 = decrypt_state->table[0x27] ^
          DecryptionTable[(out_3 >> 0x18) + 0x800] ^ DecryptionTable[(out_2 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(out_1 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(out_0 & 0xff) + 0xb00];
  uVar7 = decrypt_state->table[0x20] ^
          DecryptionTable[(uVar1 >> 0x18) + 0x800] ^ DecryptionTable[(uVar2 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar5 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar6 & 0xff) + 0xb00];
  uVar4 = decrypt_state->table[0x21] ^
          DecryptionTable[(uVar6 >> 0x18) + 0x800] ^ DecryptionTable[(uVar1 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar2 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar5 & 0xff) + 0xb00];
  uVar3 = decrypt_state->table[0x22] ^
          DecryptionTable[(uVar5 >> 0x18) + 0x800] ^ DecryptionTable[(uVar6 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar1 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar2 & 0xff) + 0xb00];
  uVar2 = decrypt_state->table[0x23] ^
          DecryptionTable[(uVar2 >> 0x18) + 0x800] ^ DecryptionTable[(uVar5 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar6 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar1 & 0xff) + 0xb00];
  uVar5 = decrypt_state->table[0x1c] ^
          DecryptionTable[(uVar7 >> 0x18) + 0x800] ^ DecryptionTable[(uVar2 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar3 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar4 & 0xff) + 0xb00];
  uVar1 = decrypt_state->table[0x1d] ^
          DecryptionTable[(uVar4 >> 0x18) + 0x800] ^ DecryptionTable[(uVar7 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar2 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar3 & 0xff) + 0xb00];
  uVar6 = decrypt_state->table[0x1e] ^
          DecryptionTable[(uVar3 >> 0x18) + 0x800] ^ DecryptionTable[(uVar4 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar7 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar2 & 0xff) + 0xb00];
  uVar3 = decrypt_state->table[0x1f] ^
          DecryptionTable[(uVar2 >> 0x18) + 0x800] ^ DecryptionTable[(uVar3 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar4 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar7 & 0xff) + 0xb00];
  uVar2 = decrypt_state->table[0x18] ^
          DecryptionTable[(uVar5 >> 0x18) + 0x800] ^ DecryptionTable[(uVar3 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar6 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar1 & 0xff) + 0xb00];
  uVar7 = decrypt_state->table[0x19] ^
          DecryptionTable[(uVar1 >> 0x18) + 0x800] ^ DecryptionTable[(uVar5 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar3 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar6 & 0xff) + 0xb00];
  uVar4 = decrypt_state->table[0x1a] ^
          DecryptionTable[(uVar6 >> 0x18) + 0x800] ^ DecryptionTable[(uVar1 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar5 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar3 & 0xff) + 0xb00];
  uVar1 = decrypt_state->table[0x1b] ^
          DecryptionTable[(uVar3 >> 0x18) + 0x800] ^ DecryptionTable[(uVar6 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar1 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar5 & 0xff) + 0xb00];
  uVar6 = decrypt_state->table[0x14] ^
          DecryptionTable[(uVar2 >> 0x18) + 0x800] ^ DecryptionTable[(uVar1 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar4 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar7 & 0xff) + 0xb00];
  uVar5 = decrypt_state->table[0x15] ^
          DecryptionTable[(uVar7 >> 0x18) + 0x800] ^ DecryptionTable[(uVar2 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar1 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar4 & 0xff) + 0xb00];
  uVar3 = decrypt_state->table[0x16] ^
          DecryptionTable[(uVar4 >> 0x18) + 0x800] ^ DecryptionTable[(uVar7 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar2 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar1 & 0xff) + 0xb00];
  uVar2 = decrypt_state->table[0x17] ^
          DecryptionTable[(uVar1 >> 0x18) + 0x800] ^ DecryptionTable[(uVar4 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar7 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar2 & 0xff) + 0xb00];
  uVar4 = decrypt_state->table[0x10] ^
          DecryptionTable[(uVar6 >> 0x18) + 0x800] ^ DecryptionTable[(uVar2 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar3 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar5 & 0xff) + 0xb00];
  uVar1 = decrypt_state->table[0x11] ^
          DecryptionTable[(uVar5 >> 0x18) + 0x800] ^ DecryptionTable[(uVar6 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar2 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar3 & 0xff) + 0xb00];
  uVar7 = decrypt_state->table[0x12] ^
          DecryptionTable[(uVar3 >> 0x18) + 0x800] ^ DecryptionTable[(uVar5 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar6 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar2 & 0xff) + 0xb00];
  uVar3 = decrypt_state->table[0x13] ^
          DecryptionTable[(uVar2 >> 0x18) + 0x800] ^ DecryptionTable[(uVar3 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar5 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar6 & 0xff) + 0xb00];
  uVar2 = decrypt_state->table[0xc] ^
          DecryptionTable[(uVar4 >> 0x18) + 0x800] ^ DecryptionTable[(uVar3 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar7 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar1 & 0xff) + 0xb00];
  uVar6 = decrypt_state->table[0xd] ^
          DecryptionTable[(uVar1 >> 0x18) + 0x800] ^ DecryptionTable[(uVar4 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar3 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar7 & 0xff) + 0xb00];
  uVar5 = decrypt_state->table[0xe] ^
          DecryptionTable[(uVar7 >> 0x18) + 0x800] ^ DecryptionTable[(uVar1 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar4 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar3 & 0xff) + 0xb00];
  uVar1 = decrypt_state->table[0xf] ^
          DecryptionTable[(uVar3 >> 0x18) + 0x800] ^ DecryptionTable[(uVar7 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar1 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar4 & 0xff) + 0xb00];
  uVar7 = decrypt_state->table[8] ^
          DecryptionTable[(uVar2 >> 0x18) + 0x800] ^ DecryptionTable[(uVar1 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar5 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar6 & 0xff) + 0xb00];
  uVar4 = decrypt_state->table[9] ^
          DecryptionTable[(uVar6 >> 0x18) + 0x800] ^ DecryptionTable[(uVar2 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar1 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar5 & 0xff) + 0xb00];
  uVar3 = decrypt_state->table[10] ^
          DecryptionTable[(uVar5 >> 0x18) + 0x800] ^ DecryptionTable[(uVar6 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar2 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar1 & 0xff) + 0xb00];
  uVar5 = decrypt_state->table[0xb] ^
          DecryptionTable[(uVar1 >> 0x18) + 0x800] ^ DecryptionTable[(uVar5 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar6 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar2 & 0xff) + 0xb00];
  uVar2 = decrypt_state->table[4] ^
          DecryptionTable[(uVar7 >> 0x18) + 0x800] ^ DecryptionTable[(uVar5 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar3 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar4 & 0xff) + 0xb00];
  uVar1 = decrypt_state->table[5] ^
          DecryptionTable[(uVar4 >> 0x18) + 0x800] ^ DecryptionTable[(uVar7 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar5 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar3 & 0xff) + 0xb00];
  uVar6 = decrypt_state->table[6] ^
          DecryptionTable[(uVar3 >> 0x18) + 0x800] ^ DecryptionTable[(uVar4 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar7 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar5 & 0xff) + 0xb00];
  uVar3 = decrypt_state->table[7] ^
          DecryptionTable[(uVar5 >> 0x18) + 0x800] ^ DecryptionTable[(uVar3 >> 0x10 & 0xff) + 0x900]
          ^ DecryptionTable[(uVar4 >> 8 & 0xff) + 0xa00] ^ DecryptionTable[(uVar7 & 0xff) + 0xb00];
  out_0 = decrypt_state->table[0] ^
          DecryptionTable[(uVar2 >> 0x18) + 0xc00] ^ DecryptionTable[(uVar3 >> 0x10 & 0xff) + 0xd00]
          ^ DecryptionTable[(uVar6 >> 8 & 0xff) + 0xe00] ^ DecryptionTable[(uVar1 & 0xff) + 0xf00];
  out_1 = decrypt_state->table[1] ^
          DecryptionTable[(uVar1 >> 0x18) + 0xc00] ^ DecryptionTable[(uVar2 >> 0x10 & 0xff) + 0xd00]
          ^ DecryptionTable[(uVar3 >> 8 & 0xff) + 0xe00] ^ DecryptionTable[(uVar6 & 0xff) + 0xf00];
  out_2 = decrypt_state->table[2] ^
          DecryptionTable[(uVar6 >> 0x18) + 0xc00] ^ DecryptionTable[(uVar1 >> 0x10 & 0xff) + 0xd00]
          ^ DecryptionTable[(uVar2 >> 8 & 0xff) + 0xe00] ^ DecryptionTable[(uVar3 & 0xff) + 0xf00];
  out_3 = decrypt_state->table[3] ^
          DecryptionTable[(uVar3 >> 0x18) + 0xc00] ^ DecryptionTable[(uVar6 >> 0x10 & 0xff) + 0xd00]
          ^ DecryptionTable[(uVar1 >> 8 & 0xff) + 0xe00] ^ DecryptionTable[(uVar2 & 0xff) + 0xf00];
finalization:
  *output = out_0;
  output[1] = out_1;
  output[2] = out_2;
  output[3] = out_3;
  return 0;
}
unsigned char xor_bytes[] = { 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0xff, 0xff, 0xff, 0xff, 0x14, 0xac, 0x5c, 0x00, 0x1a, 0xac, 0x5c, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xc9, 0xad, 0x5c, 0x00, 0xcf, 0xad, 0x5c, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xa3, 0xb0, 0x5c, 0x00, 0x00, 0x00, 0x00, 0x01 };
astruct_16* decrypt_state;

char* read_file(const char* path, size_t* sizePtr) {
    FILE* file = fopen(path, "rb");
    if (file == nullptr) {
        printf("unable to open file");
        exit(1);
    }
    fseek(file, 0l, SEEK_END);
    size_t size = ftell(file);
    if (sizePtr != nullptr) {
        *sizePtr = size;
    }
    rewind(file);
    // if (size < sizeof(astruct_16)) {
    //     size = sizeof(astruct_16);
    // }
    char* output = (char*)malloc(size + 1);
    if (output == nullptr) {
        printf("unable to allocate memory %d", size+1);
        exit(1);
    }
    fread(output, size, size, file);
    fclose(file);
    output[size] = 0;
    return output;
}

void decrypt(char* input, size_t size, char* output, astruct_16* decryption_state) {
    size_t i = 0;
    for (; i + 16 <= size; i += 16) {
        decrypt_10((uint*)(input + i), (uint*)(output + i), decryption_state);
    }
    for (; i < size; i += 1) {
        output[i] = input[i] ^ xor_bytes[i % 16];
    }
}


void decrypt_file(const std::filesystem::path& rootpath, const std::filesystem::path& path) {
    if (path.extension() != ".png") {
        return;
    }
    std::string str = path.generic_string();
    if (str.find("decrypt") != std::string::npos) {
        return;
    }

    auto rel = std::filesystem::relative(path, rootpath);

    auto output_pth = "./decrypt" / rel;
    std::filesystem::create_directories(output_pth.parent_path());
    auto output_path = (output_pth).generic_string();
    std::cout << str << " -> " << output_path << '\n';

    size_t encrypted_size = 0;
    printf("reading\n");
    char* encrypted = read_file(str.c_str(), &encrypted_size);
    printf("read\n");

    char* decrypted = (char*)malloc(encrypted_size + 1);
    decrypted[encrypted_size] = 0;

    printf("decrypting\n");
    decrypt(encrypted, encrypted_size, decrypted, decrypt_state);
    free(encrypted);
    printf("decrypted\n");


    FILE* output_file = fopen(output_path.c_str(), "wb");
    if (output_file == nullptr) {
        printf("unable to open file %s", output_path.c_str());
        exit(1);
    }
    fwrite(decrypted, 1, encrypted_size, output_file);
    fclose(output_file);
    free(decrypted);
}

void walk_dir(const std::filesystem::path& rootpath, const std::filesystem::path& path) {    
    for (const auto& child: std::filesystem::directory_iterator(path)) {
        if (child.is_directory()) {
            walk_dir(rootpath, child.path());
        }
        if (child.is_regular_file()) {
            decrypt_file(rootpath, child.path());   
        }
    }
}

int main(int argc, char const *argv[]) {
    decrypt_state = (astruct_16*)read_file("bigseed.bin", nullptr);
    // decrypt_file("files/Ch02_Face01.png");
    // return 0;
    // char *test_string = read_file("text.txt", nullptr);
    // printf("read file:\n%s\n\n", test_string);

    char* path = "./files";
    walk_dir(path, path);

    
//     // printf("decrypting\n");

    
//     size_t encrypted_size = 0;
//     // char* encrypted = read_file("Ch02_Face01.png", &encrypted_size);
//     char* encrypted = read_file("WrongWay.png", &encrypted_size);
    
//     char* decrypted = (char*)malloc(encrypted_size + 1);
//     *decrypted = encrypted_size;

//     printf("decrypting\n");
//     decrypt(encrypted, encrypted_size, decrypted, decrypt_state);
//     printf("decrypted\n");

//     printf("> %s" , decrypted);

//     FILE* output_file = fopen("./what.png", "wb");
//     if (output_file == nullptr) {
//         printf("error");
//         exit(1);
//     }
//     size_t written = fwrite(decrypted, 1, encrypted_size, output_file);
//     printf("written %zd", written);

//     fclose(output_file);


    // char* input = encrypted;
    // char output[17];
    // output[16] = 0;
    // decrypt_10((uint*) input, (uint*)output, decrypt_state);
    // printf("%s", output);

    // printf("hello %0x\n", sizeof(astruct_16));
}


