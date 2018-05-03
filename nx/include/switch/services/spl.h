/**
 * @file spl.h
 * @brief Security Processor Liaison (spl*) service IPC wrapper.
 * @author SciresM
 * @copyright libnx Authors
 */
#pragma once
#include "../types.h"

typedef enum {
    SplConfigItem_DisableProgramVerification = 1,
    SplConfigItem_DramId = 2,
    SplConfigItem_SecurityEngineIrqNumber = 3,
    SplConfigItem_Version = 4,
    SplConfigItem_HardwareType = 5,
    SplConfigItem_IsRetail = 6,
    SplConfigItem_IsRecoveryBoot = 7,
    SplConfigItem_DeviceId = 8,
    SplConfigItem_BootReason = 9,
    SplConfigItem_MemoryArrange = 10,
    SplConfigItem_IsDebugMode = 11,
    SplConfigItem_KernelMemoryConfiguration = 12,
    SplConfigItem_IsChargerHiZModeEnabled = 13,
    SplConfigItem_IsKiosk = 14,
    SplConfigItem_NewHardwareType = 15,
    SplConfigItem_NewKeyGeneration = 16,
    SplConfigItem_Package2Hash = 17
} SplConfigItem;

Result csrngInitialize(void);
void csrngExit(void);

Result csrngGetRandomBytes(void *out, size_t out_size);

Result splInitialize(void);
void splExit(void);
Result splCryptoInitialize(void);
void splCryptoExit(void);
Result splEsInitialize(void);
void splEsExit(void);
Result splSslInitialize(void);
void splSslExit(void);
Result splFsInitialize(void);
void splFsExit(void);
Result splManuInitialize(void);
void splManuExit(void);

Result splGetConfig(SplConfigItem config_item, u64 *out_config);
Result splUserExpMod(void *input, void *modulus, void *exp, size_t exp_size, void *dst);
Result splSetConfig(SplConfigItem config_item, u64 value);
Result splGetRandomBytes(void *out, size_t out_size);
Result splIsDevelopment(u8 *out_is_development);
Result splSetSharedData(u32 value);
Result splGetSharedData(u32 *out_value);

Result splCryptoGenerateAesKek(void *wrapped_kek, u32 key_generation, u32 option, void *out_sealed_kek);
Result splCryptoLoadAesKey(void *sealed_kek, void *wrapped_key, u32 keyslot);
Result splCryptoGenerateAesKey(void *sealed_kek, void *wrapped_key, void *out_sealed_key);
Result splCryptoDecryptAesKey(void *wrapped_key, u32 key_generation, u32 option, void *out_sealed_key);
Result splCryptoCryptAesCtr(void *ctr, void *input, void *output, size_t size);
Result splCryptoComputeCmac(void *input, size_t size, u32 keyslot, void *out_cmac);
Result splCryptoLockAesEngine(u32 *out_keyslot);
Result splCryptoUnlockAesEngine(u32 keyslot);
Result splCryptoGetSecurityEngineEvent(Handle *out_event);

Result splRsaDecryptPrivateKey(void *sealed_kek, void *wrapped_key, void *wrapped_rsa_key, size_t wrapped_rsa_key_size, u32 version, void *dst, size_t dst_size);

Result splEsLoadRsaOaepKey(void *sealed_kek, void *wrapped_key, void *wrapped_rsa_key, size_t wrapped_rsa_key_size);
Result splEsUnwrapRsaOaepWrappedTitlekey(void *rsa_wrapped_titlekey, void *modulus, void *label_hash, size_t label_hash_size, u32 key_generation, void *out_sealed_titlekey);
Result splEsUnwrapAesWrappedTitlekey(void *aes_wrapped_titlekey, u32 key_generation, void *out_sealed_titlekey);
Result splEsImportRsaKey(void *sealed_kek, void *wrapped_key, void *wrapped_rsa_key, size_t wrapped_rsa_key_size);
Result splEsSecureExpMod(void *input, void *modulus, void *dst);

Result splSslImportRsaKey(void *sealed_kek, void *wrapped_key, void *wrapped_rsa_key, size_t wrapped_rsa_key_size);
Result splSslSecureExpMod(void *input, void *modulus, void *dst);

Result splFsLoadSecureExpModKey(void *sealed_kek, void *wrapped_key, void *wrapped_rsa_key, size_t wrapped_rsa_key_size);
Result splFsSecureExpMod(void *input, void *modulus, void *dst);
Result splFsGenerateSpecificAesKey(void *wrapped_key, u32 key_generation, u32 option, void *out_sealed_key);
Result splFsLoadTitlekey(void *sealed_titlekey, u32 keyslot);
Result splFsGetPackage2Hash(void *out_hash);

Result splManuEncryptRsaKeyForImport(void *sealed_kek_pre, void *wrapped_key_pre, void *sealed_kek_post, void *wrapped_kek_post, u32 option, void *wrapped_rsa_key, void *out_wrapped_rsa_key, size_t rsa_key_size);
