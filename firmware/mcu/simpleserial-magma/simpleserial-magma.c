#include "gost-magma-independant.h"
#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAGMA_KEY_SIZE 32   // 256 бит
#define MAGMA_BLOCK_SIZE 8  // 64 бит
#define MAX_KEY_SLOTS 10
#define ROUND_KEYS 32       // 32 раундовых ключа

typedef struct {
    uint32_t round_keys[ROUND_KEYS];  // 32 раундовых ключа по 32 бита
} magma_ctx_t;

static magma_ctx_t magma_ctx;
static uint16_t num_encryption_rounds = 32;
static uint8_t key_storage[MAX_KEY_SLOTS][MAGMA_KEY_SIZE];
static uint8_t current_key_slot = 0;

// Функция развертки 256-битного ключа
void GOST_MAGMA_SetKey(const uint8_t* key) {
    // Преобразование 256-битного ключа в 32 раундовых ключа
    for (int i = 0; i < 8; i++) {
        magma_ctx.round_keys[i] =
            ((uint32_t)key[4 * i] << 24) |
            ((uint32_t)key[4 * i + 1] << 16) |
            ((uint32_t)key[4 * i + 2] << 8) |
            (uint32_t)key[4 * i + 3];
    }

    // Повторяем ключи для 32 раундов
    for (int i = 8; i < 24; i++) {
        magma_ctx.round_keys[i] = magma_ctx.round_keys[i % 8];
    }

    // Обратный порядок для последних 8 раундов
    for (int i = 0; i < 8; i++) {
        magma_ctx.round_keys[24 + i] = magma_ctx.round_keys[7 - i];
    }
}

// Основные функции SimpleSerial
uint8_t get_mask(uint8_t* m, uint8_t len) {
    for (uint8_t i = 0; i < len; i++) {
        m[i] ^= 0x55;
    }
    return 0x00;
}

uint8_t get_key(uint8_t* k, uint8_t len) {
    if (len != MAGMA_KEY_SIZE) return SS_ERR_LEN;
    GOST_MAGMA_SetKey(k);
    volatile uint8_t* vk = k;
    for (uint8_t i = 0; i < len; i++) {
        vk[i] = 0;
    }
    return 0x00;
}

uint8_t add_key(uint8_t* data, uint8_t len) {
    if (len != MAGMA_KEY_SIZE + 1) return SS_ERR_LEN;
    uint8_t slot = data[0];
    if (slot >= MAX_KEY_SLOTS) return SS_ERR_LEN;
    memcpy(key_storage[slot], data + 1, MAGMA_KEY_SIZE);
    return 0x00;
}

uint8_t use_key(uint8_t* data, uint8_t len) {
    if (len != 1) return SS_ERR_LEN;
    uint8_t slot = data[0];
    if (slot >= MAX_KEY_SLOTS) return SS_ERR_LEN;
    current_key_slot = slot;
    GOST_MAGMA_SetKey(key_storage[slot]);
    return 0x00;
}

uint8_t get_stored_key(uint8_t* data, uint8_t len) {
    if (len != 1) return SS_ERR_LEN;
    uint8_t slot = data[0];
    if (slot >= MAX_KEY_SLOTS) return SS_ERR_LEN;
    simpleserial_put('k', MAGMA_KEY_SIZE, key_storage[slot]);
    return 0x00;
}

uint8_t get_pt(uint8_t* pt, uint8_t len) {
    if (len != MAGMA_BLOCK_SIZE) return SS_ERR_LEN;
    gost_magma_enc_pretrigger(pt);
    trigger_high();
#ifdef ADD_JITTER
    for (volatile uint8_t k = 0; k < (*pt & 0x0F); k++);
#endif
    GOST_MAGMA_Encrypt(&magma_ctx, pt);
    trigger_low();
    gost_magma_enc_posttrigger(pt);
    simpleserial_put('r', MAGMA_BLOCK_SIZE, pt);
    return 0x00;
}

uint8_t reset(uint8_t* x, uint8_t len) {
    memset(&magma_ctx, 0, sizeof(magma_ctx));
    num_encryption_rounds = 32;
    memset(key_storage, 0, sizeof(key_storage));
    current_key_slot = 0;
    return 0x00;
}

uint8_t enc_multi_getpt(uint8_t* pt, uint8_t len) {
    if (len != MAGMA_BLOCK_SIZE) return SS_ERR_LEN;
    gost_magma_enc_pretrigger(pt);
    for (uint16_t i = 0; i < num_encryption_rounds; i++) {
        trigger_high();
        GOST_MAGMA_Encrypt(&magma_ctx, pt);
        trigger_low();
#ifdef ADD_JITTER
        for (volatile uint8_t k = 0; k < (*pt & 0x03); k++);
#endif
    }
    gost_magma_enc_posttrigger(pt);
    simpleserial_put('r', MAGMA_BLOCK_SIZE, pt);
    return 0;
}

uint8_t enc_multi_setnum(uint8_t* t, uint8_t len) {
    if (len != 2) return SS_ERR_LEN;
    num_encryption_rounds = (t[0] << 8) | t[1];
    if (num_encryption_rounds > 1000 || num_encryption_rounds == 0) {
        num_encryption_rounds = 32;
    }
    return 0;
}

#if SS_VER == SS_VER_2_1
uint8_t magma(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t* buf) {
    uint8_t req_len = 0;
    uint8_t err = 0;
    uint8_t mask_len = 0;
    if (scmd & 0x04) {
        mask_len = buf[req_len];
        req_len += 1 + mask_len;
        if (req_len > len) return SS_ERR_LEN;
        err = get_mask(buf + req_len - mask_len, mask_len);
        if (err) return err;
    }
    if (scmd & 0x02) {
        req_len += MAGMA_KEY_SIZE;
        if (req_len > len) return SS_ERR_LEN;
        err = get_key(buf + req_len - MAGMA_KEY_SIZE, MAGMA_KEY_SIZE);
        if (err) return err;
    }
    if (scmd & 0x01) {
        req_len += MAGMA_BLOCK_SIZE;
        if (req_len > len) return SS_ERR_LEN;
        err = get_pt(buf + req_len - MAGMA_BLOCK_SIZE, MAGMA_BLOCK_SIZE);
        if (err) return err;
    }
    if (len != req_len) return SS_ERR_LEN;
    return 0x00;
}
#endif

int main(void) {
    uint8_t tmp[MAGMA_KEY_SIZE] = { DEFAULT_MAGMA_KEY };
    platform_init();
    init_uart();
    trigger_setup();

    // Инициализация ключа по умолчанию в слот 0
    uint8_t init_data[MAGMA_KEY_SIZE + 1] = { 0 };
    init_data[0] = 0; // Слот 0
    memcpy(init_data + 1, tmp, MAGMA_KEY_SIZE);
    add_key(init_data, sizeof(init_data));
    use_key((uint8_t[]) { 0 }, 1);
    memset(tmp, 0, MAGMA_KEY_SIZE);

    simpleserial_init();

#if SS_VER == SS_VER_2_1
    simpleserial_addcmd(0x01, MAGMA_KEY_SIZE, magma);
#else
    simpleserial_addcmd('k', MAGMA_KEY_SIZE, get_key);
    simpleserial_addcmd('p', MAGMA_BLOCK_SIZE, get_pt);
    simpleserial_addcmd('x', 0, reset);
    simpleserial_addcmd('a', MAGMA_KEY_SIZE + 1, add_key);
    simpleserial_addcmd('u', 1, use_key);
    simpleserial_addcmd('g', 1, get_stored_key);
    simpleserial_addcmd_flags('m', 18, get_mask, CMD_FLAG_LEN);
    simpleserial_addcmd('s', 2, enc_multi_setnum);
    simpleserial_addcmd('f', MAGMA_BLOCK_SIZE, enc_multi_getpt);
#endif

    while (1) {
        simpleserial_get();
    }
}