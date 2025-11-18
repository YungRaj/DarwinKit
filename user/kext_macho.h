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

#include <types.h>

#include "api_util.h"
#include "macho.h"

class MachO;

namespace xnu {
class Kernel;

class KextMachO : public MachO {
public:
    explicit KextMachO(UIntPtr base);
    explicit KextMachO(UIntPtr base, Offset slide);

    explicit KextMachO(const char* path, Offset slide);
    explicit KextMachO(const char* path);

    ~KextMachO() = default;

    virtual void ParseLinkedit();

    virtual bool ParseLoadCommands();

    virtual void ParseMachO();

private:
    xnu::Kernel* kernel;
};

}; // namespace xnu
