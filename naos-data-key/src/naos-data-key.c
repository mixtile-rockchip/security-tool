/* SPDX-License-Identifier: MIT */
/* Persist an opaque sealed Trusted Key; this program never calls the TEE.
 *
 * misc is exactly 4 MiB. Slot A: [0x30000,0x40000), B: [0x40000,0x50000).
 * Each 64 KiB slot has this canonical little-endian, version-1 format:
 *   0: magic[8]="NAOSDK01"  8: u32 version=1  12: u32 header_bytes=128
 *  16: u64 generation>0    24: u32 state (1=initializing, 2=ready)
 *  28: u32 blob_bytes      32: u32 key_bytes=64  36: u32 sector_bytes=512
 *  40: u64 data_offset_sectors=0  48: u32 cipher=1 (AES-XTS)
 *  52: u32 IV=1 (plain64)   56..95: zero
 *  96: SHA256[32]          128: opaque ASCII hex blob, then zero padding
 * SHA256 covers all 65536 bytes with bytes 96..127 treated as zero. It detects
 * storage corruption; authentication of the sealed blob belongs to the TEE.
 * No UUID, partition geometry, plaintext key, or key rotation is supported.
 */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/fs.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include "naos-system-key-record.h"

#define MISC_BYTES UINT64_C(4194304)
#define SLOT_BYTES ((size_t)65536)
#define HEADER_BYTES ((size_t)128)
#define CHECKSUM_OFFSET ((size_t)96)
#define CHECKSUM_BYTES ((size_t)32)
#define INITIALIZING UINT32_C(1)
#define READY UINT32_C(2)
static const off_t slot_offsets[2] = {0x30000, 0x40000};
static const unsigned char magic[8] = "NAOSDK01";

struct records {
    unsigned char *slot[2];
    bool zero[2], valid[2];
    int selected;
};

static int reject(const char *message)
{
    fprintf(stderr, "naos-data-key: %s\n", message);
    return -1;
}

static int failed(const char *message)
{
    fprintf(stderr, "naos-data-key: %s: %s\n", message, strerror(errno));
    return -1;
}

static uint32_t get32(const unsigned char *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint64_t get64(const unsigned char *p)
{
    uint64_t result = 0;
    for (unsigned int i = 0; i < 8; ++i)
        result |= (uint64_t)p[i] << (i * 8);
    return result;
}

static void put32(unsigned char *p, uint32_t value)
{
    for (unsigned int i = 0; i < 4; ++i)
        p[i] = (unsigned char)(value >> (i * 8));
}

static void put64(unsigned char *p, uint64_t value)
{
    for (unsigned int i = 0; i < 8; ++i)
        p[i] = (unsigned char)(value >> (i * 8));
}

static bool all_zero(const unsigned char *data, size_t length)
{
    for (size_t i = 0; i < length; ++i)
        if (data[i] != 0)
            return false;
    return true;
}

static bool hex_blob(const unsigned char *data, size_t length)
{
    /* keyctl pipe emits hex; tolerate one trailing LF without normalizing it. */
    if (length && data[length - 1] == '\n')
        --length;
    if (!length || length % 2)
        return false;
    for (size_t i = 0; i < length; ++i)
        if (!((data[i] >= '0' && data[i] <= '9') ||
              (data[i] >= 'a' && data[i] <= 'f') ||
              (data[i] >= 'A' && data[i] <= 'F')))
            return false;
    return true;
}

static int checksum(const unsigned char *slot, unsigned char result[32])
{
    static const unsigned char zeros[32];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int length = 0;
    int ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, slot, CHECKSUM_OFFSET) == 1 &&
             EVP_DigestUpdate(ctx, zeros, CHECKSUM_BYTES) == 1 &&
             EVP_DigestUpdate(ctx, slot + HEADER_BYTES, SLOT_BYTES - HEADER_BYTES) == 1 &&
             EVP_DigestFinal_ex(ctx, result, &length) == 1 && length == CHECKSUM_BYTES;
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : reject("SHA256 operation failed");
}

/* 1: canonical valid record, 0: invalid record, -1: crypto/runtime error. */
static int valid_record(const unsigned char *slot)
{
    unsigned char actual[32];
    uint32_t state = get32(slot + 24), length = get32(slot + 28);
    if (memcmp(slot, magic, sizeof(magic)) || get32(slot + 8) != 1 ||
        get32(slot + 12) != HEADER_BYTES || get64(slot + 16) == 0 ||
        (state != INITIALIZING && state != READY) || !length ||
        length > SLOT_BYTES - HEADER_BYTES || get32(slot + 32) != 64 ||
        get32(slot + 36) != 512 || get64(slot + 40) != 0 ||
        get32(slot + 48) != 1 || get32(slot + 52) != 1 ||
        !all_zero(slot + 56, CHECKSUM_OFFSET - 56) ||
        !hex_blob(slot + HEADER_BYTES, length) ||
        !all_zero(slot + HEADER_BYTES + length, SLOT_BYTES - HEADER_BYTES - length))
        return 0;
    if (checksum(slot, actual) < 0)
        return -1;
    return CRYPTO_memcmp(actual, slot + CHECKSUM_OFFSET, CHECKSUM_BYTES) == 0;
}

static int read_at(int fd, unsigned char *data, size_t length, off_t offset)
{
    size_t done = 0;
    while (done < length) {
        ssize_t count = pread(fd, data + done, length - done, offset + (off_t)done);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            if (count == 0)
                errno = EIO;
            return failed("read failed");
        }
        done += (size_t)count;
    }
    return 0;
}

static int load_records(int fd, struct records *records)
{
    records->selected = -1;
    for (int i = 0; i < 2; ++i) {
        records->slot[i] = malloc(SLOT_BYTES);
        if (!records->slot[i])
            return failed("allocate record buffer");
        if (read_at(fd, records->slot[i], SLOT_BYTES, slot_offsets[i]) < 0)
            return -1;
        records->zero[i] = all_zero(records->slot[i], SLOT_BYTES);
        int valid = valid_record(records->slot[i]);
        if (valid < 0)
            return -1;
        records->valid[i] = valid != 0;
        if (records->valid[i] && (records->selected < 0 ||
            get64(records->slot[i] + 16) > get64(records->slot[records->selected] + 16)))
            records->selected = i;
    }
    if (records->valid[0] && records->valid[1]) {
        if (get64(records->slot[0] + 16) == get64(records->slot[1] + 16) &&
            memcmp(records->slot[0], records->slot[1], SLOT_BYTES))
            return reject("conflicting records at the same generation");
        uint32_t length = get32(records->slot[0] + 28);
        if (length != get32(records->slot[1] + 28) ||
            memcmp(records->slot[0] + HEADER_BYTES, records->slot[1] + HEADER_BYTES, length))
            return reject("records contain different sealed keys; key replacement is not supported");
    }
    if (records->selected < 0 && !(records->zero[0] && records->zero[1]))
        return reject("no valid record; refusing to reset nonzero key storage");
    return 0;
}

static int sync_data(int fd)
{
    while (fdatasync(fd) < 0) {
        if (errno != EINTR)
            return failed("fdatasync failed");
    }
    return 0;
}

static int persist_slot(int fd, int index, const unsigned char *slot)
{
    size_t done = 0;
    unsigned char *actual = malloc(SLOT_BYTES);
    if (!actual)
        return failed("allocate readback buffer");
    int result = -1;
    while (done < SLOT_BYTES) {
        ssize_t count = pwrite(fd, slot + done, SLOT_BYTES - done, slot_offsets[index] + (off_t)done);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            if (count == 0)
                errno = EIO;
            failed("record write failed");
            goto out;
        }
        done += (size_t)count;
    }
    if (sync_data(fd) < 0 || read_at(fd, actual, SLOT_BYTES, slot_offsets[index]) < 0)
        goto out;
    if (valid_record(actual) != 1 || memcmp(actual, slot, SLOT_BYTES)) {
        reject("record readback verification failed");
        goto out;
    }
    result = 0;
out:
    free(actual);
    return result;
}

static int create_record(int fd, const char *blob_path, const struct records *records)
{
    if (records->selected >= 0 || !records->zero[0] || !records->zero[1])
        return reject("initialization requires two entirely zero key slots");
    int input = open(blob_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (input < 0)
        return failed("open sealed blob");
    struct stat info;
    unsigned char *slot = calloc(1, SLOT_BYTES);
    int result = -1;
    if (!slot) {
        failed("allocate new record");
        goto out;
    }
    if (fstat(input, &info) < 0) {
        failed("stat sealed blob");
        goto out;
    }
    if (!S_ISREG(info.st_mode) || info.st_size <= 0 ||
        (uint64_t)info.st_size > SLOT_BYTES - HEADER_BYTES) {
        reject("sealed blob must be a nonempty bounded ordinary file");
        goto out;
    }
    size_t length = (size_t)info.st_size;
    if (read_at(input, slot + HEADER_BYTES, length, 0) < 0)
        goto out;
    if (!hex_blob(slot + HEADER_BYTES, length)) {
        reject("sealed blob must contain an even number of hexadecimal characters");
        goto out;
    }
    memcpy(slot, magic, sizeof(magic));
    put32(slot + 8, 1);
    put32(slot + 12, (uint32_t)HEADER_BYTES);
    put64(slot + 16, 1);
    put32(slot + 24, INITIALIZING);
    put32(slot + 28, (uint32_t)length);
    put32(slot + 32, 64);
    put32(slot + 36, 512);
    put32(slot + 48, 1);
    put32(slot + 52, 1);
    if (checksum(slot, slot + CHECKSUM_OFFSET) < 0)
        goto out;
    if (persist_slot(fd, 0, slot) == 0 && persist_slot(fd, 1, slot) == 0)
        result = 0;
out:
    free(slot);
    close(input);
    return result;
}

static int mark_ready(int fd, const struct records *records)
{
    if (records->selected < 0)
        return reject("cannot mark empty storage ready");
    const unsigned char *current = records->slot[records->selected];
    if (get32(current + 24) == READY && records->valid[0] && records->valid[1] &&
        !memcmp(records->slot[0], records->slot[1], SLOT_BYTES))
        return 0;
    uint64_t generation = get64(current + 16);
    if (generation == UINT64_MAX)
        return reject("record generation cannot advance");
    unsigned char *next = malloc(SLOT_BYTES);
    if (!next)
        return failed("allocate ready record");
    memcpy(next, current, SLOT_BYTES);
    put64(next + 16, generation + 1);
    put32(next + 24, READY);
    int first = records->selected ^ 1;
    int result = -1;
    if (checksum(next, next + CHECKSUM_OFFSET) == 0 &&
        persist_slot(fd, first, next) == 0 && persist_slot(fd, first ^ 1, next) == 0)
        result = 0;
    free(next);
    return result;
}

static int export_blob(int fd, const char *path, const struct records *records)
{
    if (records->selected < 0)
        return reject("cannot export empty key storage");
    struct stat target, device;
    if (fstat(fd, &device) < 0)
        return failed("stat device");
    if (lstat(path, &target) == 0) {
        if (!S_ISREG(target.st_mode) || (device.st_dev == target.st_dev && device.st_ino == target.st_ino))
            return reject("export target must be a separate ordinary file");
    } else if (errno != ENOENT) {
        return failed("stat export target");
    }
    char *temporary = NULL;
    if (asprintf(&temporary, "%s.tmp.XXXXXX", path) < 0)
        return failed("allocate export path");
    int output = mkstemp(temporary), result = -1;
    if (output < 0) {
        failed("create export file");
        goto out;
    }
    if (fchmod(output, 0600) < 0) {
        failed("set export permissions");
        goto out;
    }
    const unsigned char *slot = records->slot[records->selected];
    size_t length = get32(slot + 28), done = 0;
    while (done < length) {
        ssize_t count = write(output, slot + HEADER_BYTES + done, length - done);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            if (count == 0)
                errno = EIO;
            failed("write export failed");
            goto out;
        }
        done += (size_t)count;
    }
    if (sync_data(output) < 0)
        goto out;
    if (rename(temporary, path) < 0) {
        failed("publish export file");
        goto out;
    }
    result = 0;
out:
    if (output >= 0)
        close(output);
    if (result != 0 && output >= 0)
        unlink(temporary);
    free(temporary);
    return result;
}

static void usage(FILE *stream)
{
    fputs("Usage: naos-data-key {status|export|init|ready} --device PATH\n"
          "       export additionally requires --output PATH\n"
          "       init additionally requires --blob PATH\n"
          "       --allow-regular-file permits only 4 MiB ordinary test files\n"
          "       naos-data-key system {read|write|erase} ...\n", stream);
}

int main(int argc, char **argv)
{
    const char *device = NULL, *blob = NULL, *output = NULL;
    bool allow_regular = false;
    if (argc >= 2 && !strcmp(argv[1], "system"))
        return naos_system_key_main(argc, argv);
    if (argc == 2 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h"))) {
        usage(stdout);
        return EXIT_SUCCESS;
    }
    if (argc < 2 || (strcmp(argv[1], "status") && strcmp(argv[1], "export") &&
                     strcmp(argv[1], "init") && strcmp(argv[1], "ready"))) {
        usage(stderr);
        return EXIT_FAILURE;
    }
    for (int i = 2; i < argc; ++i) {
        if (!strcmp(argv[i], "--allow-regular-file") && !allow_regular) {
            allow_regular = true;
            continue;
        }
        const char **value = NULL;
        if (!strcmp(argv[i], "--device")) value = &device;
        else if (!strcmp(argv[i], "--blob")) value = &blob;
        else if (!strcmp(argv[i], "--output")) value = &output;
        if (!value || *value || i + 1 >= argc || !argv[i + 1][0]) {
            reject("invalid or duplicate arguments");
            return EXIT_FAILURE;
        }
        *value = argv[++i];
    }
    bool initialize = !strcmp(argv[1], "init"), exporting = !strcmp(argv[1], "export");
    bool writing = initialize || !strcmp(argv[1], "ready");
    if (!device || (initialize != (blob != NULL)) || (exporting != (output != NULL))) {
        reject("command arguments do not match the requested operation");
        return EXIT_FAILURE;
    }
    int fd = open(device, (writing ? O_RDWR : O_RDONLY) | O_CLOEXEC);
    if (fd < 0) {
        failed("open device");
        return EXIT_FAILURE;
    }
    int result = -1;
    struct records records = {0};
    struct stat info;
    uint64_t capacity = 0;
    if (fstat(fd, &info) < 0) {
        failed("stat device");
        goto out;
    }
    if (S_ISBLK(info.st_mode)) {
        if (ioctl(fd, BLKGETSIZE64, &capacity) < 0) {
            failed("read device capacity");
            goto out;
        }
    } else if (allow_regular && S_ISREG(info.st_mode) && info.st_size >= 0) {
        capacity = (uint64_t)info.st_size;
    } else {
        reject("device must be a block device; ordinary test files require --allow-regular-file");
        goto out;
    }
    if (capacity != MISC_BYTES) {
        reject("misc capacity must be exactly 4 MiB");
        goto out;
    }
    while (flock(fd, writing ? LOCK_EX : LOCK_SH) < 0) {
        if (errno != EINTR) {
            failed("lock device");
            goto out;
        }
    }
    if (load_records(fd, &records) < 0)
        goto out;
    if (!strcmp(argv[1], "status")) {
        const char *state = records.selected < 0 ? "empty" :
            get32(records.slot[records.selected] + 24) == READY ? "ready" : "initializing";
        result = puts(state) < 0 ? failed("write status") : 0;
    } else if (initialize) {
        result = create_record(fd, blob, &records);
    } else if (exporting) {
        result = export_blob(fd, output, &records);
    } else {
        result = mark_ready(fd, &records);
    }
out:
    free(records.slot[0]);
    free(records.slot[1]);
    close(fd);
    return result == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
