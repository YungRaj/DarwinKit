/*
 * Copyright (c) YungRaj
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "strparse.h"

#ifdef __KERNEL__

int isspace(int c) {
    return (c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r' || c == ' ' ? 1 : 0);
}

#endif

static UInt32 log2(UInt64 value) {
    UInt32 shift = 0;

    while (value >>= 1)
        ++shift;

    return shift;
}

int hex_digit(char ch) {
    if ('0' <= ch && '9' >= ch)
        return ch - '0';
    else if ('A' <= ch && 'F' >= ch)
        return ch - 'A' + 0xa;
    else if ('a' <= ch && 'f' >= ch)
        return ch - 'a' + 0xa;

    return -1;
}

char* strnchar(char* str, UInt32 len, char ch) {
    char* s = str;
    char* end = str + len;

    while (s < end) {
        if (*s == ch)
            return s;

        if (*s == 0)
            return nullptr;

        s++;
    }

    return nullptr;
}

enum strtoint_result strtoint(char* str, UInt32 len, bool sign, bool is_signed, UInt32 base,
                              UInt64* value, char** end) {
    enum strtoint_result result = STRTOINT_OK;

    char* last = str + len;

    bool negate = false;

    UInt64 _value = 0;

    if (last == str)
        goto no_chars;

    if (sign && (str[0] == '+' || str[0] == '-')) {
        negate = (str[0] == '-');
        str++;
    } else if (str[0] == '0' && (str[1] == 'x' || str[1] == 'o' || str[1] == 'b')) {
        if (str[1] == 'x')
            base = 16;
        if (str[1] == 'o')
            base = 8;
        if (str[1] == 'b')
            base = 2;

        str += 2;
    }

    int d;

    if (last == str)
        goto no_chars;

    d = hex_digit(*str);

    if (d < 0 || d >= base)
        goto no_chars;

    while (str != last && *str != 0) {
        d = hex_digit(*str);

        if (d < 0 || d >= base) {
            result = STRTOINT_BADDIGIT;

            goto fail;
        }

        UInt64 new_value = _value * base + d;

        if (is_signed) {
            UInt64 max = (UInt64)(negate ? INTMAX_MIN : INTMAX_MAX);

            if (new_value > max) {
                result = STRTOINT_OVERFLOW;

                goto fail;
            }
        } else if (new_value < _value) {
            result = STRTOINT_OVERFLOW;

            goto fail;
        }

        _value = new_value;
        str++;
    }

    if (negate)
        _value = (UInt64)(-(int64_t)_value);

    *value = _value;

    *end = str;

    return result;

no_chars:
    result = STRTOINT_NODIGITS;
fail:
    *end = str;

    return result;
}

enum strtodata_result strtodata(char* str, UInt32 base, void* data, UInt32* size, char** end) {
    enum strtodata_result result = STRTODATA_OK;

    char* start = str;

    if (str[0] == '0' && (str[1] == 'x' || str[1] == 'o' || str[1] == 'b')) {
        if (str[1] == 'x')
            base = 16;
        if (str[1] == 'o')
            base = 8;
        if (str[1] == 'b')
            base = 2;

        str += 2;
    }

    UInt32 bits_per_digit = log2(base);

    UInt8* p = (UInt8*)data;

    UInt32 left = (p == nullptr ? 0 : *size);

    UInt32 realsize = 0;

    do {
        UInt8 byte = 0;

        for (UInt32 i = 0; i < 8 / bits_per_digit; i++) {
            int d = hex_digit(*str);

            if (d < 0 || d >= base) {
                if (i == 0) {
                    if (str == start)
                        result = STRTODATA_NODIGITS;
                    else
                        result = STRTODATA_BADDIGIT;

                    goto no_digits;
                }

                result = STRTODATA_NEEDDIGIT;

                goto fail;
            }

            byte |= d << (8 - (i + 1) * bits_per_digit);

            str++;
        }

        realsize++;

        if (left > 0) {
            *p = byte;
            p++;

            left--;
        }
    } while (*str != 0);

no_digits:
    *size = realsize;

fail:
    *end = str;

    return result;
}

enum strparse_result strreplace(char* str, char find, char replace) {
    int digits = 0;

    for (int i = 0; i < strlen(str); i++) {
        if (str[i] == find) {
            str[i] = replace;

            digits++;
        }
    }

    if (!digits)
        return STRPARSE_NODIGITS;

    return STRPARSE_OK;
}

#ifdef __KERNEL__

char* strdup(char* s) {
    Size l;
    char* t;

    if (s == nullptr)
        return nullptr;

    l = strlen(s);
    t = new char[l + 1];

    memcpy(t, s, l);

    t[l] = '\0';

    return t;
}

char* strstr(char* string, char* substring) {
    char *a, *b;

    /* First scan quickly through the two strings looking for a
     * single-character match.  When it's found, then compare the
     * rest of the substring.
     */

    b = substring;

    if (*b == 0) {
        return string;
    }

    for (; *string != 0; string += 1) {
        if (*string != *b) {
            continue;
        }

        a = string;

        while (1) {
            if (*b == 0) {
                return string;
            }

            if (*a++ != *b++) {
                break;
            }
        }

        b = substring;
    }

    return nullptr;
}

#endif

char* strtokmul(char* input, char* delimiter) {
    static char* string;

    if (input != nullptr)
        string = input;

    if (string == nullptr)
        return string;

    char* end = strstr(string, delimiter);

    if (end == nullptr) {
        char* temp = string;

        string = nullptr;

        return temp;
    }

    char* temp = string;

    *end = '\0';

    string = end + strlen(delimiter);

    return temp;
}

char* ltrim(char* s) {
    while (isspace(*s))
        s++;

    return s;
}

char* rtrim(char* s) {
    char* back = s + strlen(s);

    while (isspace(*--back))
        ;

    *(back + 1) = '\0';

    return s;
}

char* trim(char* s) {
    return rtrim(ltrim(s));
}

char* deblank(char* input) {
    int i, j;

    char* output = input;

    for (i = 0, j = 0; i < strlen(input); i++, j++) {
        if (input[i] != ' ')
            output[j] = input[i];
        else
            j--;
    }

    output[j] = '\0';

    return output;
}

/*
#include <string.h>

int main()
{
    UInt64 value;

    char *s = "0xfffffff007b6b668";
    char *end = nullptr;

    UInt8 *data;
    UInt32 data_len;

    enum strtoint_result sir;
    enum strtodata_result sdr;

    sdr = strtodata(s, 16, nullptr, &data_len, &end);

    data = malloc(data_len);

    printf("data_len = 0x%x\n", data_len);

    sdr = strtodata(s, 16, data, &data_len, &end);

    for(UInt32 i = 0; i < data_len; i++)
        printf("%x", data[i]);

    printf("\n");

    printf("0x%llx\n", *(UInt64*) data);

    sir = strtoint(s, strlen(s), true, false, 16, &value, &end);

    printf("0x%llx\n", value);
}
*/