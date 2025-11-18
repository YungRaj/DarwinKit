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
static void EmptyDeleter(T t) {
    // Does nothing here because we don't wanna destroy the T object
    // We just wanna destroy the Pair
}

template <typename T, typename Y, void (*DeleterT)(T) = EmptyDeleter<T>,
          void (*DeleterY)(Y) = EmptyDeleter<Y>>
class Pair {
public:
    T first;
    Y second;

    Pair(T first, Y second) : first(first), second(second) {}

    ~Pair() {
        Deleter(this);
    }

    static Pair<T, Y>* create(T first, Y second) {
        return new Pair(first, second);
    }

    static void Deleter(Pair<T, Y>* pair) {
        DeleterT(pair->first);
        DeleterY(pair->second);
    }
};
