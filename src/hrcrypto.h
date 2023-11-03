#ifdef __cplusplus 
extern "C" {
#endif

#include "hrtypes.h"
#include "../lib/incbin/incbin.h"

struct DecryptState {
    char unknown_1[256];
    uint table[64];
    uint unknown_2;
    uint current_decrypt_state;
    char iteration_determinant;
};

INCBIN(DecryptState, DecriptionState, "resources/decryption/state.bin");
INCBIN(unsigned char, DecryptionXor, "resources/decryption/xor.bin");
INCBIN(unsigned int, DecryptionTable, "resources/decryption/table.bin");

#ifdef __cplusplus 
}
#endif



const uint* decryption_table = gDecryptionTableData;
const DecryptState* decrypt_state = gDecriptionStateData;
const uchar* xor_bytes = gDecryptionXorData;


uint decrypt_16(uint *input,uint *output, const DecryptState *decrypt_state)
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
    const uint *small_state;

    small_state = decrypt_state->table + decrypt_state->current_decrypt_state * 4;
    if ((decrypt_state->iteration_determinant & 2) == 0) {
        printf("Not reverse engineered");
        exit(1);
        return (uint)((size_t)small_state & 0xffff0000);
    }
    if ((decrypt_state->iteration_determinant & 2) == 0) {
        printf("Not reverse engineered");
        exit(1);
        // iterate_decrypt_state((uint *)decrypt_state);
        // decrypt_state->iteration_determinant = decrypt_state->iteration_determinant ^ 3;
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
                decryption_table[(out_0 >> 0x18) + 0x800] ^
                decryption_table[(out_3 >> 0x10 & 0xff) + 0x900] ^
                decryption_table[(out_2 >> 8 & 0xff) + 0xa00] ^ decryption_table[(out_1 & 0xff) + 0xb00]
        ;
        uVar1 = decrypt_state->table[0x35] ^
                decryption_table[(out_1 >> 0x18) + 0x800] ^
                decryption_table[(out_0 >> 0x10 & 0xff) + 0x900] ^
                decryption_table[(out_3 >> 8 & 0xff) + 0xa00] ^ decryption_table[(out_2 & 0xff) + 0xb00]
        ;
        uVar5 = decrypt_state->table[0x36] ^
                decryption_table[(out_2 >> 0x18) + 0x800] ^
                decryption_table[(out_1 >> 0x10 & 0xff) + 0x900] ^
                decryption_table[(out_0 >> 8 & 0xff) + 0xa00] ^ decryption_table[(out_3 & 0xff) + 0xb00]
        ;
        uVar3 = decrypt_state->table[0x37] ^
                decryption_table[(out_3 >> 0x18) + 0x800] ^
                decryption_table[(out_2 >> 0x10 & 0xff) + 0x900] ^
                decryption_table[(out_1 >> 8 & 0xff) + 0xa00] ^ decryption_table[(out_0 & 0xff) + 0xb00]
        ;
        out_0 = decrypt_state->table[0x30] ^
                decryption_table[(uVar2 >> 0x18) + 0x800] ^
                decryption_table[(uVar3 >> 0x10 & 0xff) + 0x900] ^
                decryption_table[(uVar5 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar1 & 0xff) + 0xb00]
        ;
        out_1 = decrypt_state->table[0x31] ^
                decryption_table[(uVar1 >> 0x18) + 0x800] ^
                decryption_table[(uVar2 >> 0x10 & 0xff) + 0x900] ^
                decryption_table[(uVar3 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar5 & 0xff) + 0xb00]
        ;
        out_2 = decrypt_state->table[0x32] ^
                decryption_table[(uVar5 >> 0x18) + 0x800] ^
                decryption_table[(uVar1 >> 0x10 & 0xff) + 0x900] ^
                decryption_table[(uVar2 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar3 & 0xff) + 0xb00]
        ;
        out_3 = decrypt_state->table[0x33] ^
                decryption_table[(uVar3 >> 0x18) + 0x800] ^
                decryption_table[(uVar5 >> 0x10 & 0xff) + 0x900] ^
                decryption_table[(uVar1 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar2 & 0xff) + 0xb00]
        ;
    }
    uVar3 = decrypt_state->table[0x2c] ^
            decryption_table[(out_0 >> 0x18) + 0x800] ^
            decryption_table[(out_3 >> 0x10 & 0xff) + 0x900] ^
            decryption_table[(out_2 >> 8 & 0xff) + 0xa00] ^ decryption_table[(out_1 & 0xff) + 0xb00];
    uVar2 = decrypt_state->table[0x2d] ^
            decryption_table[(out_1 >> 0x18) + 0x800] ^
            decryption_table[(out_0 >> 0x10 & 0xff) + 0x900] ^
            decryption_table[(out_3 >> 8 & 0xff) + 0xa00] ^ decryption_table[(out_2 & 0xff) + 0xb00];
    uVar1 = decrypt_state->table[0x2e] ^
            decryption_table[(out_2 >> 0x18) + 0x800] ^
            decryption_table[(out_1 >> 0x10 & 0xff) + 0x900] ^
            decryption_table[(out_0 >> 8 & 0xff) + 0xa00] ^ decryption_table[(out_3 & 0xff) + 0xb00];
    uVar5 = decrypt_state->table[0x2f] ^
            decryption_table[(out_3 >> 0x18) + 0x800] ^
            decryption_table[(out_2 >> 0x10 & 0xff) + 0x900] ^
            decryption_table[(out_1 >> 8 & 0xff) + 0xa00] ^ decryption_table[(out_0 & 0xff) + 0xb00];
    out_0 = decrypt_state->table[0x28] ^
            decryption_table[(uVar3 >> 0x18) + 0x800] ^
            decryption_table[(uVar5 >> 0x10 & 0xff) + 0x900] ^
            decryption_table[(uVar1 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar2 & 0xff) + 0xb00];
    out_1 = decrypt_state->table[0x29] ^
            decryption_table[(uVar2 >> 0x18) + 0x800] ^
            decryption_table[(uVar3 >> 0x10 & 0xff) + 0x900] ^
            decryption_table[(uVar5 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar1 & 0xff) + 0xb00];
    out_2 = decrypt_state->table[0x2a] ^
            decryption_table[(uVar1 >> 0x18) + 0x800] ^
            decryption_table[(uVar2 >> 0x10 & 0xff) + 0x900] ^
            decryption_table[(uVar3 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar5 & 0xff) + 0xb00];
    out_3 = decrypt_state->table[0x2b] ^
            decryption_table[(uVar5 >> 0x18) + 0x800] ^
            decryption_table[(uVar1 >> 0x10 & 0xff) + 0x900] ^
            decryption_table[(uVar2 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar3 & 0xff) + 0xb00];
    }
    uVar1 = decrypt_state->table[0x24] ^
            decryption_table[(out_0 >> 0x18) + 0x800] ^ decryption_table[(out_3 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(out_2 >> 8 & 0xff) + 0xa00] ^ decryption_table[(out_1 & 0xff) + 0xb00];
    uVar6 = decrypt_state->table[0x25] ^
            decryption_table[(out_1 >> 0x18) + 0x800] ^ decryption_table[(out_0 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(out_3 >> 8 & 0xff) + 0xa00] ^ decryption_table[(out_2 & 0xff) + 0xb00];
    uVar5 = decrypt_state->table[0x26] ^
            decryption_table[(out_2 >> 0x18) + 0x800] ^ decryption_table[(out_1 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(out_0 >> 8 & 0xff) + 0xa00] ^ decryption_table[(out_3 & 0xff) + 0xb00];
    uVar2 = decrypt_state->table[0x27] ^
            decryption_table[(out_3 >> 0x18) + 0x800] ^ decryption_table[(out_2 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(out_1 >> 8 & 0xff) + 0xa00] ^ decryption_table[(out_0 & 0xff) + 0xb00];
    uVar7 = decrypt_state->table[0x20] ^
            decryption_table[(uVar1 >> 0x18) + 0x800] ^ decryption_table[(uVar2 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar5 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar6 & 0xff) + 0xb00];
    uVar4 = decrypt_state->table[0x21] ^
            decryption_table[(uVar6 >> 0x18) + 0x800] ^ decryption_table[(uVar1 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar2 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar5 & 0xff) + 0xb00];
    uVar3 = decrypt_state->table[0x22] ^
            decryption_table[(uVar5 >> 0x18) + 0x800] ^ decryption_table[(uVar6 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar1 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar2 & 0xff) + 0xb00];
    uVar2 = decrypt_state->table[0x23] ^
            decryption_table[(uVar2 >> 0x18) + 0x800] ^ decryption_table[(uVar5 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar6 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar1 & 0xff) + 0xb00];
    uVar5 = decrypt_state->table[0x1c] ^
            decryption_table[(uVar7 >> 0x18) + 0x800] ^ decryption_table[(uVar2 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar3 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar4 & 0xff) + 0xb00];
    uVar1 = decrypt_state->table[0x1d] ^
            decryption_table[(uVar4 >> 0x18) + 0x800] ^ decryption_table[(uVar7 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar2 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar3 & 0xff) + 0xb00];
    uVar6 = decrypt_state->table[0x1e] ^
            decryption_table[(uVar3 >> 0x18) + 0x800] ^ decryption_table[(uVar4 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar7 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar2 & 0xff) + 0xb00];
    uVar3 = decrypt_state->table[0x1f] ^
            decryption_table[(uVar2 >> 0x18) + 0x800] ^ decryption_table[(uVar3 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar4 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar7 & 0xff) + 0xb00];
    uVar2 = decrypt_state->table[0x18] ^
            decryption_table[(uVar5 >> 0x18) + 0x800] ^ decryption_table[(uVar3 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar6 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar1 & 0xff) + 0xb00];
    uVar7 = decrypt_state->table[0x19] ^
            decryption_table[(uVar1 >> 0x18) + 0x800] ^ decryption_table[(uVar5 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar3 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar6 & 0xff) + 0xb00];
    uVar4 = decrypt_state->table[0x1a] ^
            decryption_table[(uVar6 >> 0x18) + 0x800] ^ decryption_table[(uVar1 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar5 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar3 & 0xff) + 0xb00];
    uVar1 = decrypt_state->table[0x1b] ^
            decryption_table[(uVar3 >> 0x18) + 0x800] ^ decryption_table[(uVar6 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar1 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar5 & 0xff) + 0xb00];
    uVar6 = decrypt_state->table[0x14] ^
            decryption_table[(uVar2 >> 0x18) + 0x800] ^ decryption_table[(uVar1 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar4 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar7 & 0xff) + 0xb00];
    uVar5 = decrypt_state->table[0x15] ^
            decryption_table[(uVar7 >> 0x18) + 0x800] ^ decryption_table[(uVar2 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar1 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar4 & 0xff) + 0xb00];
    uVar3 = decrypt_state->table[0x16] ^
            decryption_table[(uVar4 >> 0x18) + 0x800] ^ decryption_table[(uVar7 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar2 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar1 & 0xff) + 0xb00];
    uVar2 = decrypt_state->table[0x17] ^
            decryption_table[(uVar1 >> 0x18) + 0x800] ^ decryption_table[(uVar4 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar7 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar2 & 0xff) + 0xb00];
    uVar4 = decrypt_state->table[0x10] ^
            decryption_table[(uVar6 >> 0x18) + 0x800] ^ decryption_table[(uVar2 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar3 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar5 & 0xff) + 0xb00];
    uVar1 = decrypt_state->table[0x11] ^
            decryption_table[(uVar5 >> 0x18) + 0x800] ^ decryption_table[(uVar6 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar2 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar3 & 0xff) + 0xb00];
    uVar7 = decrypt_state->table[0x12] ^
            decryption_table[(uVar3 >> 0x18) + 0x800] ^ decryption_table[(uVar5 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar6 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar2 & 0xff) + 0xb00];
    uVar3 = decrypt_state->table[0x13] ^
            decryption_table[(uVar2 >> 0x18) + 0x800] ^ decryption_table[(uVar3 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar5 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar6 & 0xff) + 0xb00];
    uVar2 = decrypt_state->table[0xc] ^
            decryption_table[(uVar4 >> 0x18) + 0x800] ^ decryption_table[(uVar3 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar7 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar1 & 0xff) + 0xb00];
    uVar6 = decrypt_state->table[0xd] ^
            decryption_table[(uVar1 >> 0x18) + 0x800] ^ decryption_table[(uVar4 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar3 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar7 & 0xff) + 0xb00];
    uVar5 = decrypt_state->table[0xe] ^
            decryption_table[(uVar7 >> 0x18) + 0x800] ^ decryption_table[(uVar1 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar4 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar3 & 0xff) + 0xb00];
    uVar1 = decrypt_state->table[0xf] ^
            decryption_table[(uVar3 >> 0x18) + 0x800] ^ decryption_table[(uVar7 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar1 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar4 & 0xff) + 0xb00];
    uVar7 = decrypt_state->table[8] ^
            decryption_table[(uVar2 >> 0x18) + 0x800] ^ decryption_table[(uVar1 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar5 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar6 & 0xff) + 0xb00];
    uVar4 = decrypt_state->table[9] ^
            decryption_table[(uVar6 >> 0x18) + 0x800] ^ decryption_table[(uVar2 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar1 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar5 & 0xff) + 0xb00];
    uVar3 = decrypt_state->table[10] ^
            decryption_table[(uVar5 >> 0x18) + 0x800] ^ decryption_table[(uVar6 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar2 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar1 & 0xff) + 0xb00];
    uVar5 = decrypt_state->table[0xb] ^
            decryption_table[(uVar1 >> 0x18) + 0x800] ^ decryption_table[(uVar5 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar6 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar2 & 0xff) + 0xb00];
    uVar2 = decrypt_state->table[4] ^
            decryption_table[(uVar7 >> 0x18) + 0x800] ^ decryption_table[(uVar5 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar3 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar4 & 0xff) + 0xb00];
    uVar1 = decrypt_state->table[5] ^
            decryption_table[(uVar4 >> 0x18) + 0x800] ^ decryption_table[(uVar7 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar5 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar3 & 0xff) + 0xb00];
    uVar6 = decrypt_state->table[6] ^
            decryption_table[(uVar3 >> 0x18) + 0x800] ^ decryption_table[(uVar4 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar7 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar5 & 0xff) + 0xb00];
    uVar3 = decrypt_state->table[7] ^
            decryption_table[(uVar5 >> 0x18) + 0x800] ^ decryption_table[(uVar3 >> 0x10 & 0xff) + 0x900]
            ^ decryption_table[(uVar4 >> 8 & 0xff) + 0xa00] ^ decryption_table[(uVar7 & 0xff) + 0xb00];
    out_0 = decrypt_state->table[0] ^
            decryption_table[(uVar2 >> 0x18) + 0xc00] ^ decryption_table[(uVar3 >> 0x10 & 0xff) + 0xd00]
            ^ decryption_table[(uVar6 >> 8 & 0xff) + 0xe00] ^ decryption_table[(uVar1 & 0xff) + 0xf00];
    out_1 = decrypt_state->table[1] ^
            decryption_table[(uVar1 >> 0x18) + 0xc00] ^ decryption_table[(uVar2 >> 0x10 & 0xff) + 0xd00]
            ^ decryption_table[(uVar3 >> 8 & 0xff) + 0xe00] ^ decryption_table[(uVar6 & 0xff) + 0xf00];
    out_2 = decrypt_state->table[2] ^
            decryption_table[(uVar6 >> 0x18) + 0xc00] ^ decryption_table[(uVar1 >> 0x10 & 0xff) + 0xd00]
            ^ decryption_table[(uVar2 >> 8 & 0xff) + 0xe00] ^ decryption_table[(uVar3 & 0xff) + 0xf00];
    out_3 = decrypt_state->table[3] ^
            decryption_table[(uVar3 >> 0x18) + 0xc00] ^ decryption_table[(uVar6 >> 0x10 & 0xff) + 0xd00]
            ^ decryption_table[(uVar1 >> 8 & 0xff) + 0xe00] ^ decryption_table[(uVar2 & 0xff) + 0xf00];
    finalization:
    *output = out_0;
    output[1] = out_1;
    output[2] = out_2;
    output[3] = out_3;
    return 0;
}

void decrypt(const char* input, size_t size, char* output, const DecryptState* decryption_state) {
    size_t i = 0;
    for (; i + 16 <= size; i += 16) {
        decrypt_16((uint*)(input + i), (uint*)(output + i), decryption_state);
    }
    for (; i < size; i += 1) {
        output[i] = input[i] ^ xor_bytes[i % 16];
    }
}