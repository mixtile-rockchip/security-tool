/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "naos-system-key-record.h"

#define MISC_BYTES (4U * 1024U * 1024U)
#define SYSTEM_BLOB_BYTES 100U
#define SYSTEM_HEADER_BYTES 40U
#define SYSTEM_KEY_BYTES 32U
#define RECORD_BYTES 65536U
#define IMPORT_OFFSET 0x20000U
#define BLOB_A_OFFSET 0x50000U
#define BLOB_B_OFFSET 0x60000U

static void clear_memory(void *memory, size_t size)
{
    volatile unsigned char *p = memory;
    while (size--)
        *p++ = 0;
}

static int read_exact(int fd, void *buffer, size_t length, off_t offset)
{
    size_t done = 0;
    while (done < length) {
        ssize_t count = pread(fd, (unsigned char *)buffer + done,
                              length - done, offset + (off_t)done);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return -1;
        done += (size_t)count;
    }
    return 0;
}

static int write_exact(int fd, const void *buffer, size_t length, off_t offset)
{
    size_t done = 0;
    while (done < length) {
        ssize_t count = pwrite(fd, (const unsigned char *)buffer + done,
                               length - done, offset + (off_t)done);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return -1;
        done += (size_t)count;
    }
    return 0;
}

static int synchronize(int fd)
{
    int result;
    do { result = fdatasync(fd); } while (result < 0 && errno == EINTR);
    return result;
}

static int private_record(const char *path, unsigned char *record)
{
    struct stat info;
    unsigned char extra;
    ssize_t count;
    int result = -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0)
        return -1;
    if (fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_nlink != 1 ||
        (info.st_mode & 077) || info.st_size != RECORD_BYTES)
        goto out;
    if (read_exact(fd, record, RECORD_BYTES, 0))
        goto out;
    do { count = pread(fd, &extra, 1, RECORD_BYTES); } while (count < 0 && errno == EINTR);
    if (!count)
        result = 0;
out:
    close(fd);
    return result;
}

static int create_record(const char *path, const unsigned char *record)
{
    int result = -1;
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    if (!fchmod(fd, 0600) && !write_exact(fd, record, RECORD_BYTES, 0) &&
        !synchronize(fd))
        result = 0;
    if (close(fd))
        result = -1;
    if (result)
        unlink(path);
    return result;
}

#ifndef NAOS_SYSTEM_KEY_TEST_FILE
static int partition_is_misc(dev_t device)
{
    char path[128], data[4096], *line, *state;
    size_t used = 0;
    int fd, result = 0;
    snprintf(path, sizeof(path), "/sys/dev/block/%u:%u/uevent",
             major(device), minor(device));
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    while (used < sizeof(data) - 1) {
        ssize_t count = read(fd, data + used, sizeof(data) - 1 - used);
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0)
            goto out;
        if (!count)
            break;
        used += (size_t)count;
    }
    if (used == sizeof(data) - 1)
        goto out;
    data[used] = '\0';
    for (line = strtok_r(data, "\n", &state); line; line = strtok_r(NULL, "\n", &state)) {
        if (!strcmp(line, "PARTNAME=misc"))
            result = 1;
    }
out:
    close(fd);
    return result;
}
#endif

static int open_misc(const char *path, int writing)
{
    struct stat info;
    int locked;
    int fd = open(path, (writing ? O_RDWR : O_RDONLY) | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0)
        return -1;
    if (fstat(fd, &info))
        goto fail;
#ifdef NAOS_SYSTEM_KEY_TEST_FILE
    /* Compile-time fixture backend only. Production never accepts a file. */
    if (!S_ISREG(info.st_mode) || info.st_nlink != 1 || info.st_size != MISC_BYTES)
        goto fail;
#else
    {
        uint64_t bytes = 0;
        if (!S_ISBLK(info.st_mode) || ioctl(fd, BLKGETSIZE64, &bytes) ||
            bytes != MISC_BYTES || !partition_is_misc(info.st_rdev))
            goto fail;
    }
#endif
    do { locked = flock(fd, LOCK_EX); } while (locked < 0 && errno == EINTR);
    if (locked)
        goto fail;
    return fd;
fail:
    close(fd);
    return -1;
}

static uint32_t get_le32(const unsigned char *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static int canonical_blob_record(const unsigned char *record)
{
    static const unsigned char magic[8] = { 'N','A','O','S','S','W','0','1' };
    unsigned char uuid_nonzero = 0;
    size_t i;
    /* The UUID remains opaque here. Only the TA authenticates its identity. */
    if (memcmp(record, magic, sizeof(magic)) || get_le32(record + 8) != 1 ||
        get_le32(record + 12) != SYSTEM_HEADER_BYTES ||
        get_le32(record + 32) != SYSTEM_KEY_BYTES || get_le32(record + 36) != 1)
        return 0;
    for (i = 16; i < 32; i++)
        uuid_nonzero |= record[i];
    if (!uuid_nonzero)
        return 0;
    for (i = SYSTEM_BLOB_BYTES; i < RECORD_BYTES; i++) {
        if (record[i])
            return 0;
    }
    return 1;
}

static int usage(const char *program)
{
    fprintf(stderr, "Usage: %s system read DEVICE {import|blob-a|blob-b} OUTPUT_RECORD\n"
                    "       %s system write DEVICE {blob-a|blob-b} INPUT_RECORD EXPECTED_RECORD\n"
                    "       %s system erase DEVICE import EXPECTED_RECORD\n"
                    "Records are exactly 65536 bytes; outputs must not exist.\n",
                    program, program, program);
    return 2;
}

int naos_system_key_main(int argc, char **argv)
{
    unsigned char *expected = NULL, *record = NULL, *current = NULL;
    off_t offset;
    int reading, writing, erasing, fd = -1, result = 1;
    if (argc < 3)
        return usage(argv[0]);
    reading = !strcmp(argv[2], "read");
    writing = !strcmp(argv[2], "write");
    erasing = !strcmp(argv[2], "erase");
    if ((!reading && !writing && !erasing) ||
        argc != (writing ? 7 : 6))
        return usage(argv[0]);
    if (!strcmp(argv[4], "import"))
        offset = IMPORT_OFFSET;
    else if (!strcmp(argv[4], "blob-a"))
        offset = BLOB_A_OFFSET;
    else if (!strcmp(argv[4], "blob-b"))
        offset = BLOB_B_OFFSET;
    else
        return usage(argv[0]);
    if ((writing && offset == IMPORT_OFFSET) || (erasing && offset != IMPORT_OFFSET))
        return usage(argv[0]);
    current = malloc(RECORD_BYTES);
    if (!current)
        goto out;
    if (!reading) {
        expected = malloc(RECORD_BYTES);
        record = calloc(1, RECORD_BYTES);
        if (!expected || !record)
            goto out;
        if (private_record(argv[writing ? 6 : 5], expected) ||
            (writing && (private_record(argv[5], record) || !canonical_blob_record(record)))) {
            fprintf(stderr, "Invalid private record or noncanonical blob record.\n");
            goto out;
        }
    }
    fd = open_misc(argv[3], !reading);
    if (fd < 0) {
        fprintf(stderr, "Device must be a 4 MiB block partition named misc.\n");
        goto out;
    }
    if (read_exact(fd, current, RECORD_BYTES, offset)) {
        fprintf(stderr, "Cannot read misc record.\n");
        goto out;
    }
    if (reading) {
        if (create_record(argv[5], current)) {
            fprintf(stderr, "Cannot create private record output.\n");
            goto out;
        }
    } else {
        if (memcmp(current, expected, RECORD_BYTES)) {
            fprintf(stderr, "Expected record differs from misc; nothing written.\n");
            goto out;
        }
        if (write_exact(fd, record, RECORD_BYTES, offset) || synchronize(fd) ||
            read_exact(fd, current, RECORD_BYTES, offset) ||
            memcmp(current, record, RECORD_BYTES)) {
            fprintf(stderr, "Misc record write or verification failed.\n");
            goto out;
        }
    }
    result = 0;
out:
    if (fd >= 0)
        close(fd); /* also releases the advisory lock */
    if (current) { clear_memory(current, RECORD_BYTES); free(current); }
    if (expected) { clear_memory(expected, RECORD_BYTES); free(expected); }
    if (record) { clear_memory(record, RECORD_BYTES); free(record); }
    return result;
}
