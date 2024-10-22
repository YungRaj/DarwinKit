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

#pragma once

#include "vector.h"

namespace std {
template <typename T>
class map {
public:
    map() {}

    ~map() {}

    T operator[](char* key) {
        return get(key);
    }

    T get(char* key) {
        for (int i = 0; i < keys.size(); i++) {
            char* k = keys.at(i);

            if (strcmp(k, key) == 0) {
                return values.at(i);
            }
        }

        return nullptr;
    }

    int find(char* key) {
        for (int i = 0; i < keys.size(); i++) {
            char* k = keys.at(i);

            if (strcmp(k, key) == 0) {
                return i;
            }
        }

        return -1;
    }

    void set(char* key, void* value) {
        int index;

        if ((index = find(key)) != -1) {
            values.set(value, index);

            return;
        }

        keys.push_back(key);
        values.push_back(value);
    }

private:
    std::vector<char*> keys;
    std::vector<T> values;
};
}; // namespace std
