// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2025 Rockchip Electronics Co. Ltd.
 */
/* NAOS stateless envelope client. No secrets are printed. */
#define _GNU_SOURCE
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <tee_client_api.h>
#include "ta_keybox.h"

static void erase(void *memory, size_t size)
{
    volatile unsigned char *p = memory;
    while (size--)
        *p++ = 0;
}

static int read_private(const char *path, unsigned char *buffer, size_t size)
{
    struct stat info;
    unsigned char extra;
    size_t used = 0;
    ssize_t count;
    int result = -1;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0)
        return -1;
    if (fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_nlink != 1 ||
        (info.st_mode & 077) || info.st_size != (off_t)size)
        goto out;
    while (used < size) {
        count = read(fd, buffer + used, size - used);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            goto out;
        used += count;
    }
    do { count = read(fd, &extra, 1); } while (count < 0 && errno == EINTR);
    if (count == 0)
        result = 0;
out:
    close(fd);
    return result;
}

static int write_private(const char *path, const unsigned char *buffer, size_t size)
{
    size_t used = 0;
    ssize_t count;
    int result = -1;
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    while (used < size) {
        count = write(fd, buffer + used, size - used);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            goto out;
        used += count;
    }
    if (fsync(fd) == 0)
        result = 0;
out:
    if (close(fd))
        result = -1;
    if (result)
        unlink(path);
    return result;
}

static int nibble(unsigned char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

int main(int argc, char **argv)
{
    static const TEEC_UUID uuid = TA_KEYBOX_UUID;
    static const unsigned char hex[] = "0123456789abcdef";
    unsigned char input[NAOS_BLOB_SIZE] = { 0 };
    unsigned char output[NAOS_BLOB_SIZE] = { 0 };
    unsigned char key[NAOS_KEY_SIZE] = { 0 };
    TEEC_Context context;
    TEEC_Session session;
    TEEC_Operation operation = { 0 };
    TEEC_Result status;
    uint32_t origin = 0, command;
    size_t i, input_size, output_size;
    int result = 1, context_ready = 0, session_ready = 0;

    if (argc != 4 || (strcmp(argv[1], "seal") && strcmp(argv[1], "unseal"))) {
        fprintf(stderr, "Usage: %s seal INPUT_KEY_HEX OUTPUT_BLOB\n"
                        "       %s unseal INPUT_BLOB OUTPUT_KEY_HEX\n"
                        "Inputs must be private regular files; output must not exist.\n",
                        argv[0], argv[0]);
        return 2;
    }
    command = !strcmp(argv[1], "seal") ? NAOS_CMD_SEAL : NAOS_CMD_UNSEAL;
    input_size = command == NAOS_CMD_SEAL ? NAOS_KEY_HEX_SIZE : NAOS_BLOB_SIZE;
    if (read_private(argv[2], input, input_size)) {
        fprintf(stderr, "Cannot read a private input of the required exact length.\n");
        goto out;
    }
    if (command == NAOS_CMD_SEAL) {
        for (i = 0; i < sizeof(key); i++) {
            int high = nibble(input[i * 2]), low = nibble(input[i * 2 + 1]);
            if (high < 0 || low < 0) {
                fprintf(stderr, "Input key must be exactly 64 lowercase hexadecimal bytes.\n");
                goto out;
            }
            key[i] = (high << 4) | low;
        }
    }
    status = TEEC_InitializeContext(NULL, &context);
    if (status != TEEC_SUCCESS)
        goto tee_error;
    context_ready = 1;
    status = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_PUBLIC,
                              NULL, NULL, &origin);
    if (status != TEEC_SUCCESS)
        goto tee_error;
    session_ready = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                            TEEC_MEMREF_TEMP_OUTPUT,
                                            TEEC_NONE, TEEC_NONE);
    operation.params[0].tmpref.buffer = command == NAOS_CMD_SEAL ? key : input;
    operation.params[0].tmpref.size = command == NAOS_CMD_SEAL ? sizeof(key) : input_size;
    operation.params[1].tmpref.buffer = output;
    operation.params[1].tmpref.size = command == NAOS_CMD_SEAL ? NAOS_BLOB_SIZE : sizeof(key);
    output_size = operation.params[1].tmpref.size;
    status = TEEC_InvokeCommand(&session, command, &operation, &origin);
    if (status != TEEC_SUCCESS)
        goto tee_error;
    if (operation.params[1].tmpref.size != output_size) {
        fprintf(stderr, "TA returned an invalid output length.\n");
        goto out;
    }
    if (command == NAOS_CMD_UNSEAL) {
        for (i = 0; i < sizeof(key); i++) {
            input[i * 2] = hex[output[i] >> 4];
            input[i * 2 + 1] = hex[output[i] & 15];
        }
        if (write_private(argv[3], input, NAOS_KEY_HEX_SIZE))
            goto file_error;
    } else if (write_private(argv[3], output, output_size)) {
        goto file_error;
    }
    result = 0;
    goto out;
tee_error:
    fprintf(stderr, "TEE operation failed: 0x%08x, origin %u.\n", status, origin);
    goto out;
file_error:
    fprintf(stderr, "Cannot create private output; the path must not already exist.\n");
out:
    if (session_ready) TEEC_CloseSession(&session);
    if (context_ready) TEEC_FinalizeContext(&context);
    erase(key, sizeof(key));
    erase(input, sizeof(input));
    erase(output, sizeof(output));
    return result;
}
