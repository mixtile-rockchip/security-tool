// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025 Rockchip Electronics Co. Ltd.
 */
/* NAOS stateless system-key envelope, using the SDK key derivation API. */
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <tee_api.h>
#include "ta_keybox.h"
#include "../rk_public_api/rk_derive_key_api.h"

static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24;
}

static void make_header(uint8_t header[NAOS_HEADER_SIZE])
{
    static const uint8_t magic[8] = { 'N','A','O','S','S','W','0','1' };
    static const uint8_t uuid[16] = NAOS_UUID_BYTES;
    TEE_MemMove(header, magic, sizeof(magic));
    put_le32(header + 8, 1);       /* format version */
    put_le32(header + 12, NAOS_HEADER_SIZE);
    TEE_MemMove(header + 16, uuid, sizeof(uuid));
    put_le32(header + 32, NAOS_KEY_SIZE);
    put_le32(header + 36, 1);      /* AES-256-GCM */
}

static TEE_Result wrap_key(uint32_t command, TEE_Param params[4])
{
    static const uint8_t extra[] = "naos-system-wrap-v1";
    uint8_t kek[NAOS_KEY_SIZE] = { 0 };
    uint8_t plain[NAOS_KEY_SIZE] = { 0 };
    uint8_t blob[NAOS_BLOB_SIZE] = { 0 };
    uint8_t header[NAOS_HEADER_SIZE] = { 0 };
    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    TEE_OperationHandle operation = TEE_HANDLE_NULL;
    TEE_Attribute attribute;
    TEE_Result result = TEE_ERROR_BAD_PARAMETERS;
    uint32_t length = NAOS_KEY_SIZE, tag_length = NAOS_TAG_SIZE;
    const int sealing = command == NAOS_CMD_SEAL;
    const uint32_t output_size = sealing ? NAOS_BLOB_SIZE : NAOS_KEY_SIZE;

    if (!params[0].memref.buffer || !params[1].memref.buffer ||
        params[0].memref.size != (sealing ? NAOS_KEY_SIZE : NAOS_BLOB_SIZE))
        goto out;
    if (params[1].memref.size < output_size) {
        params[1].memref.size = output_size;
        result = TEE_ERROR_SHORT_BUFFER;
        goto out;
    }
    params[1].memref.size = 0;
    make_header(header);
    /* Snapshot all REE input before validating or operating on it. */
    if (sealing) {
        TEE_MemMove(plain, params[0].memref.buffer, NAOS_KEY_SIZE);
        TEE_MemMove(blob, header, NAOS_HEADER_SIZE);
        TEE_GenerateRandom(blob + NAOS_NONCE_OFFSET, NAOS_NONCE_SIZE);
    } else {
        TEE_MemMove(blob, params[0].memref.buffer, NAOS_BLOB_SIZE);
        if (TEE_MemCompare(blob, header, NAOS_HEADER_SIZE)) {
            result = TEE_ERROR_SECURITY;
            goto out;
        }
    }
    result = rk_derive_ta_unique_key((uint8_t *)extra, sizeof(extra) - 1,
                                     kek, sizeof(kek));
    if (result != TEE_SUCCESS)
        goto out;
    result = TEE_AllocateTransientObject(TEE_TYPE_AES, 256, &object);
    if (result != TEE_SUCCESS)
        goto out;
    TEE_InitRefAttribute(&attribute, TEE_ATTR_SECRET_VALUE, kek, sizeof(kek));
    result = TEE_PopulateTransientObject(object, &attribute, 1);
    if (result != TEE_SUCCESS)
        goto out;
    result = TEE_AllocateOperation(&operation, TEE_ALG_AES_GCM,
                                   sealing ? TEE_MODE_ENCRYPT : TEE_MODE_DECRYPT,
                                   256);
    if (result != TEE_SUCCESS)
        goto out;
    result = TEE_SetOperationKey(operation, object);
    if (result != TEE_SUCCESS)
        goto out;
    result = TEE_AEInit(operation, blob + NAOS_NONCE_OFFSET, NAOS_NONCE_SIZE,
                        NAOS_TAG_SIZE * 8, NAOS_HEADER_SIZE, NAOS_KEY_SIZE);
    if (result != TEE_SUCCESS)
        goto out;
    TEE_AEUpdateAAD(operation, blob, NAOS_HEADER_SIZE);
    if (sealing) {
        result = TEE_AEEncryptFinal(operation, plain, sizeof(plain),
                                   blob + NAOS_CIPHER_OFFSET, &length,
                                   blob + NAOS_TAG_OFFSET, &tag_length);
        if (result == TEE_SUCCESS &&
            (length != NAOS_KEY_SIZE || tag_length != NAOS_TAG_SIZE))
            result = TEE_ERROR_SECURITY;
        if (result == TEE_SUCCESS)
            TEE_MemMove(params[1].memref.buffer, blob, sizeof(blob));
    } else {
        /* Authentication finishes in private memory; no speculative plaintext
         * is ever copied to a caller-controlled output buffer. */
        result = TEE_AEDecryptFinal(operation, blob + NAOS_CIPHER_OFFSET,
                                   NAOS_KEY_SIZE, plain, &length,
                                   blob + NAOS_TAG_OFFSET, NAOS_TAG_SIZE);
        if (result == TEE_SUCCESS && length != NAOS_KEY_SIZE)
            result = TEE_ERROR_SECURITY;
        if (result == TEE_SUCCESS)
            TEE_MemMove(params[1].memref.buffer, plain, sizeof(plain));
    }
    if (result == TEE_SUCCESS)
        params[1].memref.size = output_size;
out:
    if (operation != TEE_HANDLE_NULL)
        TEE_FreeOperation(operation);
    if (object != TEE_HANDLE_NULL)
        TEE_FreeTransientObject(object);
    TEE_MemFill(kek, 0, sizeof(kek));
    TEE_MemFill(plain, 0, sizeof(plain));
    TEE_MemFill(blob, 0, sizeof(blob));
    TEE_MemFill(header, 0, sizeof(header));
    return result;
}

TEE_Result TA_CreateEntryPoint(void) { return TEE_SUCCESS; }
void TA_DestroyEntryPoint(void) { }
TEE_Result TA_OpenSessionEntryPoint(uint32_t types, TEE_Param params[4], void **ctx)
{
    (void)params;
    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                                TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE))
        return TEE_ERROR_BAD_PARAMETERS;
    *ctx = NULL;
    return TEE_SUCCESS;
}
void TA_CloseSessionEntryPoint(void *ctx) { (void)ctx; }
TEE_Result TA_InvokeCommandEntryPoint(void *ctx, uint32_t command,
                                      uint32_t types, TEE_Param params[4])
{
    (void)ctx;
    if ((command != NAOS_CMD_SEAL && command != NAOS_CMD_UNSEAL) ||
        types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                  TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                  TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE))
        return TEE_ERROR_BAD_PARAMETERS;
    return wrap_key(command, params);
}
