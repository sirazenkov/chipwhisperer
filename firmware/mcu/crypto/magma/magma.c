#include <stdio.h>

typedef unsigned long long ullong;
typedef unsigned long ulong;

ulong xkey[32];
const int piBlock[8][16] = {
    {1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2},
    {8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7},
    {5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0},
    {7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12},
    {12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11},
    {11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0},
    {6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15},
    {12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1},
};

void setKey(ullong* key) {
    for (int i = 0; i < 4; ++i) {
        ulong left = key[i] >> 32;
        ulong right = key[i];
        xkey[i * 2] = xkey[i * 2 + 8] = xkey[i * 2 + 16] = xkey[31 - i * 2] = left;
        xkey[i * 2 + 1] = xkey[i * 2 + 9] = xkey[i * 2 + 17] = xkey[30 - i * 2] = right;
    }
}

ulong f(ulong a, ulong x) {
    a += x;
    int un[8];
    for (int i = 7; i > -1; i--) {
        x = a & 0xf;
        un[i] = piBlock[i][x];
        a >>= 4;
    }
    for (int i = 0; i < 7; ++i) {
        a += un[i];
        a <<= 4;
    }
    a += un[7];
    a = (a << 11) | (a >> 21);
    return a;
}

ullong encrypt(ullong data) {
    ulong right = data;
    ulong left = data >> 32;
    ulong old;
    for (int i = 0; i < 31; ++i) {
        old = right;
        right = left ^ f(right, xkey[i]);
        left = old;
    }
    left = left ^ f(right, xkey[31]);
    ullong result = left;
    result <<= 32;
    return result + right;
}

int main() {
    ullong key[4] = { 0xffeeddccbbaa9988, 0x7766554433221100, 0xf0f1f2f3f4f5f6f7, 0xf8f9fafbfcfdfeff };
    setKey(key);
    ullong text = 0xfedcba9876543210;
    ullong message = encrypt(text);
    printf("%llx\n", message);
    return 0;
}