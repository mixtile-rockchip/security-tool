/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H
#include <ta_keybox.h>
#define TA_UUID TA_KEYBOX_UUID
#define TA_FLAGS (TA_FLAG_USER_MODE | TA_FLAG_EXEC_DDR | TA_FLAG_MULTI_SESSION)
#define TA_STACK_SIZE (4 * 1024)
#define TA_DATA_SIZE (32 * 1024)
#endif
