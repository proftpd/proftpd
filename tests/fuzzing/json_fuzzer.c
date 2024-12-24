/*
 * ProFTPD - FTP server fuzzing testsuite
 * Copyright (c) 2021 The ProFTPD Project team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "json.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *new_str = (char *)malloc(size + 1);
    if (new_str == NULL) {
        return 0;
    }
    memcpy(new_str, data, size);
    new_str[size] = '\0';

    pool *p = make_sub_pool(NULL);
    if (p != NULL) {
        init_json();

        pr_json_object_t *json = pr_json_object_from_text(p, new_str);
        pr_json_object_free(json);

        const char *malformed_json = "{\"key\": \"value\",}";
        pr_json_object_t *malformed_obj = pr_json_object_from_text(p, malformed_json);
        pr_json_object_free(malformed_obj);

        const char *large_json = "{\"key\": \"value\", \"key2\": \"value2\", \"key3\": \"value3\", \"key4\": \"value4\"}";
        pr_json_object_t *large_obj = pr_json_object_from_text(p, large_json);
        pr_json_object_free(large_obj);

        const char *nested_json = "{\"key\": {\"subkey\": {\"subsubkey\": {\"subsubsubkey\": \"value\"}}}}";
        pr_json_object_t *nested_obj = pr_json_object_from_text(p, nested_json);
        pr_json_object_free(nested_obj);

        const char *invalid_utf8_json = "{\"key\": \"\x80\x81\x82\"}";
        pr_json_object_t *invalid_utf8_obj = pr_json_object_from_text(p, invalid_utf8_json);
        pr_json_object_free(invalid_utf8_obj);

        finish_json();
        destroy_pool(p);
    }

    free(new_str);
    return 0;
}
