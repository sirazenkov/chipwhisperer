#ifndef GOST_MAGMA_INDEPENDANT_H
#define GOST_MAGMA_INDEPENDANT_H

#include <stdint.h>

#define MAGMA_KEY_LENGTH 32
#define MAX_KEY_SLOTS 10  // Количество хранимых ключей

// Основные функции
void gost_magma_init(void);
void gost_magma_key(uint8_t* key);  // Для обратной совместимости

// Функции управления множеством ключей
void gost_magma_set_key(uint8_t slot, uint8_t* key);
void gost_magma_use_key(uint8_t slot);
uint8_t* gost_magma_get_key(uint8_t slot);

// Функции шифрования
void gost_magma_enc(uint8_t* block);
void gost_magma_enc_pretrigger(uint8_t* block);
void gost_magma_enc_posttrigger(uint8_t* block);
void gost_magma_mask(uint8_t* m, uint8_t len);

#endif