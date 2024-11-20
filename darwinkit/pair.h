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

#include <stddef.h>
#include <stdint.h>

template <typename T>
static void emptyDeleter(T t) {
    /* do nothing here because we don't wanna destroy the T object */
    /* we just wanna destroy the Pair */
}

template <typename T, typename Y, void (*deleterT)(T) = emptyDeleter<T>,
          void (*deleterY)(Y) = emptyDeleter<Y>>
class Pair {
public:
    T first;
    Y second;

    explicit Pair(T first, Y second) {
        first = first;
        second = second;
    }

    ~Pair() {
        deleter(this);
    }

    static Pair<T, Y>* create(T first, Y second) {
        return new Pair(first, second);
    }

    static void deleter(Pair<T, Y>* pair) {
        deleterT(pair->first);
        deleterY(pair->second);

        delete pair;
    }
};
