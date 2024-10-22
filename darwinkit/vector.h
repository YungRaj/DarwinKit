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

#ifdef __USER__

#include <vector>

#elif __KERNEL__

#include <sys/types.h>

namespace std {
template <typename T>
struct Node {
    Node<T>* next;
    Node<T>* previous;

    T t;
};

template <typename T>
class vector;

template <typename T>
T remove(typename std::vector<T>::iterator begin, typename std::vector<T>::iterator end, T t);

template <typename T>
typename std::vector<T>::iterator find(typename std::vector<T>::iterator begin,
                                       typename std::vector<T>::iterator end, T t);

template <typename T>
class vector {
public:
    class iterator {
    public:
        explicit iterator(vector<T>& vec, off_t offset) : vec(vec), current_offset(offset) {}

        off_t offset() {
            return current_offset;
        }

        T at(off_t index) {
            return vec.at(index);
        }

        T operator*() {
            return vec.at(current_offset);
        }

        T operator++() {
            return vec.at(++current_offset);
        }

        T operator++(int) {
            T tmp = vec.at(current_offset);

            ++current_offset;

            return tmp;
        }

        bool operator==(iterator other) {
            return offset() == other.offset();
        }

        bool operator!=(iterator other) {
            return offset() != other.offset();
        }

        iterator operator+(iterator& other) {
            return iterator(vec, offset() + other.offset());
        }

        iterator operator+(int other) {
            return iterator(vec, offset() + other);
        }

        iterator operator-(iterator& other) {
            return iterator(vec, offset() - other.offset());
        }

        iterator operator-(int other) {
            return iterator(vec, offset() - other);
        }

    private:
        vector<T>& vec;

        off_t current_offset;
    };

public:
    explicit vector() : head(nullptr), tail(nullptr), sz(0) {}

    ~vector() {
        clear();

        head = nullptr;
        tail = nullptr;
    }

    iterator begin() {
        return iterator(*this, 0);
    }

    iterator end() {
        return iterator(*this, size());
    }

    size_t size() {
        return sz;
    }

    bool empty() {
        return sz == 0;
    }

    T operator[](int index) {
        return this->get(index);
    }

    T at(int index) {
        Node<T>* current = head;

        if (index < 0 && index >= sz)
            return (T)nullptr;

        while (current && index) {
            current = current->next;

            index--;
        }

        if (!current)
            return (T)nullptr;

        return current->t;
    }

    int find(T t) {
        int index = 0;

        Node<T>* current = head;

        while (current) {
            if (index >= sz)
                break;
            if (current->t == t)
                return index;

            current = current->next;

            index++;
        }

        return -1;
    }

    void clear() {
        struct Node<T>* current = head;

        while (current) {
            struct Node<T>* next = current->next;

            delete current;

            current = next;
        }
    }

    void push_back(T t) {
        Node<T>* node = new Node<T>;

        node->t = t;

        if (!head && !tail) {
            head = tail = node;

            sz++;
        } else if (head) {
            Node<T>* current = head;

            while (current->next)
                current = current->next;

            current->next = node;
            node->previous = current;

            tail = node;

            sz++;
        } else {
            delete node;
        }
    }

    void insert(T t, int index) {
        Node<T>* node;
        Node<T>* current;

        node = new Node<T>;
        node->t = node;

        current = head;

        if (index < 0)
            return;

        if (!head && !tail) {
            head = tail = node;

            sz++;
        } else if (head) {
            while (current && index) {
                current = current->next;

                index--;
            }

            if (!index) {
                if (!current) {
                    tail->next = node;
                    node->previous = tail;
                } else {
                    Node<T>* previous = current->previous;

                    node->previous = previous;
                    previous->next = node;

                    node->next = current;
                    current->previous = node;
                }

                sz++;
            }
        }
    }

    void erase_internal(off_t begin, off_t end, int index) {
        Node<T>* current = head;

        if (index < 0 && index >= sz)
            return;

        while (current && index) {
            current = current->next;

            index--;
        }

        if (!index) {
            if (head == tail) {
                head = nullptr;
                tail = nullptr;
            } else if (current == head) {
                Node<T>* next = current->next;

                if (next) {
                    next->previous = nullptr;

                    head = next;
                }
            } else if (current == tail) {
                Node<T>* previous = current->previous;

                if (previous) {
                    previous->next = nullptr;

                    tail = previous;
                }
            } else {
                Node<T>* next;
                Node<T>* previous;

                next = current->next;
                previous = current->previous;

                next->previous = previous;
                previous->next = next;
            }

            sz--;

            delete current;
        }
    }

    void erase(iterator begin, iterator end, int index) {
        off_t b = begin.offset();
        off_t e = end.offset();

        if (b > index || e <= index)
            return;

        erase_internal(b, e, index);
    }

    void erase(iterator it) {
        off_t off = it.offset();

        erase(begin(), end(), off);
    }

    void erase(int index) {
        erase(begin(), end(), index);
    }

    void erase(T t, iterator it) {
        int index = find(t);

        if (index >= 0)
            erase(begin(), end(), index);
    }

    void print() {}

private:
    Node<T>* head;
    Node<T>* tail;

    size_t sz;
};

template <typename T>
T remove(typename std::vector<T>::iterator begin, typename std::vector<T>::iterator end, T t) {
    return t;
}

template <typename T>
typename std::vector<T>::iterator find(typename std::vector<T>::iterator begin,
                                       typename std::vector<T>::iterator end, T t) {
    typename vector<T>::iterator it = begin;

    while (*it) {
        T elem = *it;

        if (elem == t)
            return it;

        it++;
    }

    return end;
}
}; // namespace std

#endif
