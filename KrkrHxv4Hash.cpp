/*
    KrkrHxv4Hash.dll source code
    Calculates Kirikiri Hxv4 hashes of file names and paths
    Build using Visual Studio 2022 (v143)
    Code restored by reverse engineering by TotSamiyMisha
    Version 0.1
*/
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>

const wchar_t* salt = L"xp3hnp";

static const uint32_t IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

static const uint8_t sigma[10][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 },
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8 },
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13 },
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9 },
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11 },
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10 },
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5 },
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0 },
};

static inline uint32_t ror32(uint32_t value, uint32_t count) {
    return (value >> count) | (value << (32 - count));
}

void G(uint32_t v[16], int a, int b, int c, int d, uint32_t x, uint32_t y) {
    v[a] += v[b] + x;
    v[d] = ror32(v[d] ^ v[a], 16);
    v[c] += v[d];
    v[b] = ror32(v[b] ^ v[c], 12);
    v[a] += v[b] + y;
    v[d] = ror32(v[d] ^ v[a], 8);
    v[c] += v[d];
    v[b] = ror32(v[b] ^ v[c], 7);
}

//BLAKE2s (KiriKiri Hxv4 implementation)
void FilenameHash(unsigned int* a1, unsigned __int8* a2) {
    uint32_t v[16];
    for (int i = 0; i < 8; ++i) {
        v[i] = a1[i];
    }
    for (int i = 0; i < 8; ++i) {
        v[i + 8] = IV[i];
    }
    v[12] ^= a1[8];
    v[13] ^= a1[9];
    v[14] ^= a1[10];
    v[15] ^= a1[11];

    uint32_t m[16];
    for (int i = 0; i < 16; ++i) {
        m[i] = (uint32_t)a2[4 * i] |
            ((uint32_t)a2[4 * i + 1] << 8 ) |
            ((uint32_t)a2[4 * i + 2] << 16) |
            ((uint32_t)a2[4 * i + 3] << 24);
    }

    for (int r = 0; r < 10; ++r) {
        G(v, 0, 4, 8,  12,  m[sigma[r][0]],  m[sigma[r][1]]);
        G(v, 1, 5, 9,  13,  m[sigma[r][2]],  m[sigma[r][3]]);
        G(v, 2, 6, 10, 14,  m[sigma[r][4]],  m[sigma[r][5]]);
        G(v, 3, 7, 11, 15,  m[sigma[r][6]],  m[sigma[r][7]]);
        G(v, 0, 5, 10, 15,  m[sigma[r][8]],  m[sigma[r][9]]);
        G(v, 1, 6, 11, 12,  m[sigma[r][10]], m[sigma[r][11]]);
        G(v, 2, 7, 8,  13,  m[sigma[r][12]], m[sigma[r][13]]);
        G(v, 3, 4, 9,  14,  m[sigma[r][14]], m[sigma[r][15]]);
    }

    for (int i = 0; i < 8; ++i) {
        a1[i] ^= v[i] ^ v[i + 8];
    }
}

static inline uint64_t rol64(uint64_t value, unsigned int count) {
    return (value << count) | (value >> (64 - count));
}

void sipround(uint64_t* v0, uint64_t* v1, uint64_t* v2, uint64_t* v3) {
    *v0 += *v1;  *v1 = rol64(*v1, 13);  *v1 ^= *v0;  *v0 = rol64(*v0, 32);
    *v2 += *v3;  *v3 = rol64(*v3, 16);  *v3 ^= *v2;
    *v0 += *v3;  *v3 = rol64(*v3, 21);  *v3 ^= *v0;
    *v2 += *v1;  *v1 = rol64(*v1, 17);  *v1 ^= *v2;  *v2 = rol64(*v2, 32);
}

// SipHash (KiriKiri Hxv4 implementation)
uint64_t PathHash(const uint8_t* data, size_t len, const uint8_t key[16]) {
    uint64_t k0 = ((uint64_t*)key)[0];
    uint64_t k1 = ((uint64_t*)key)[1];

    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;

    const uint8_t* end = data + (len & ~7ULL);
    uint64_t m;

    for (; data != end; data += 8) {
        m =   ((uint64_t)data[0])
            | ((uint64_t)data[1] << 8)
            | ((uint64_t)data[2] << 16)
            | ((uint64_t)data[3] << 24)
            | ((uint64_t)data[4] << 32)
            | ((uint64_t)data[5] << 40)
            | ((uint64_t)data[6] << 48)
            | ((uint64_t)data[7] << 56);

        v3 ^= m;
        sipround(&v0, &v1, &v2, &v3);
        sipround(&v0, &v1, &v2, &v3);
        v0 ^= m;
    }

    uint64_t b = ((uint64_t)len) << 56;
    switch (len & 7) {
    case 7: b |= ((uint64_t)data[6]) << 48;
    case 6: b |= ((uint64_t)data[5]) << 40;
    case 5: b |= ((uint64_t)data[4]) << 32;
    case 4: b |= ((uint64_t)data[3]) << 24;
    case 3: b |= ((uint64_t)data[2]) << 16;
    case 2: b |= ((uint64_t)data[1]) << 8;
    case 1: b |= ((uint64_t)data[0]); break;
    default: break;
    }

    v3 ^= b;
    sipround(&v0, &v1, &v2, &v3);
    sipround(&v0, &v1, &v2, &v3);
    v0 ^= b;
    v2 ^= 0xFF;
    for (int i = 0; i < 4; i++)
        sipround(&v0, &v1, &v2, &v3);

    return v0 ^ v1 ^ v2 ^ v3;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport)
const uint8_t* get_filename_hash(const wchar_t* input_string2) {
    static uint8_t outName32[32];
    uint8_t outName[0x30] = { 0x47, 0xE6, 0x08, 0x6B, 0x85, 0xAE, 0x67, 0xBB, 0x72, 0xF3, 0x6E, 0x3C, 0x3A, 0xF5, 0x4F, 0xA5, 0x7F, 0x52, 0x0E, 0x51, 0x8C, 0x68, 0x05, 0x9B, 0xAB, 0xD9, 0x83, 0x1F, 0x19, 0xCD, 0xE0, 0x5B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    size_t len_input = wcslen(input_string2);
    size_t len_salt = wcslen(salt);
    size_t total_len = len_input + len_salt;

    wchar_t* input_string = new wchar_t[total_len + 1];
    std::wcscpy(input_string, input_string2);
    std::wcscat(input_string, salt);

    char buffer[0x40] = { 0 };

    unsigned int is_last_chunk = 0;

    size_t total_bytes = wcslen(input_string) * sizeof(wchar_t);

    const unsigned char* ptr = reinterpret_cast<const unsigned char*>(input_string);
    size_t remaining_bytes = total_bytes;
    DWORD tempSize = 0;

    while (remaining_bytes > 0) {

        size_t chunk_size = min(remaining_bytes, sizeof(buffer));

        tempSize += chunk_size;

        is_last_chunk = (remaining_bytes <= sizeof(buffer)) ? -1 : 0;

        *((DWORD*)&outName[0x20]) = tempSize;
        *((DWORD*)&outName[0x28]) = is_last_chunk;
        std::memset(buffer, 0, sizeof(buffer));

        std::memcpy(buffer, ptr, chunk_size);

        FilenameHash(reinterpret_cast<unsigned int*>(outName), reinterpret_cast<unsigned char*>(buffer));

        ptr += chunk_size;
        remaining_bytes -= chunk_size;
    }
    delete[] input_string;
    std::memcpy(outName32, outName, 32);
    return outName32;
}

extern "C" __declspec(dllexport)
uint64_t get_path_hash(const wchar_t* input) {

    uint8_t seed[16] = { 0 };

    if (wcslen(input) == 1 && input[0] == L'/') {
        uint64_t hash = PathHash((unsigned char*)salt, wcslen(salt) * 2, seed);
        unsigned char* p = reinterpret_cast<unsigned char*>(&hash);
        std::reverse(p, p + 8);
        hash = *reinterpret_cast<uint64_t*>(p);
        return hash;
    }

    size_t len_input = wcslen(input);
    size_t len_salt = wcslen(salt);
    size_t total_len = len_input + len_salt;

    wchar_t* input_string = new wchar_t[total_len + 1];
    std::wcscpy(input_string, input);
    std::wcscat(input_string, salt);

    uint64_t hash = PathHash((unsigned char*)input_string, wcslen(input_string) * 2, seed);

    unsigned char* p = reinterpret_cast<unsigned char*>(&hash);
    std::reverse(p, p + 8);
    hash = *reinterpret_cast<uint64_t*>(p);
    delete[] input_string;
    return hash;
}

