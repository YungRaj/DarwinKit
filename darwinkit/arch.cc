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

#include "arch.h"

namespace arch {
Architecture* initArchitecture() {
    static Architecture* architecture = nullptr;

    if (!architecture) {
        architecture = new Architecture();
    }

    return architecture;
}

Architecture::Architecture() : arch(arch::getCurrentArchitecture()) {}

Architecture::~Architecture() {}

bool Architecture::setInterrupts(bool enable) {
    bool success = false;

    switch (current_architecture) {
    case ARCH_x86_64:
        success = x86_64::setInterrupts(enable);

        break;
    case ARCH_arm64:
        success = arm64::setInterrupts(enable);

        break;
    default:
        break;
    }

    return success;
}

bool Architecture::setWPBit(bool enable) {
    bool success = false;

    switch (current_architecture) {
    case ARCH_x86_64:
        success = x86_64::setWPBit(enable);

        break;
    case ARCH_arm64:
        success = arm64::setWPBit(enable);

        break;
    default:
        break;
    }

    return success;
}

bool Architecture::setNXBit(bool enable) {
    bool success = false;

    switch (current_architecture) {
    case ARCH_x86_64:
        success = x86_64::setNXBit(enable);

        break;
    case ARCH_arm64:
        success = arm64::setNXBit(enable);

        break;
    default:
        break;
    }

    return success;
}

bool Architecture::setPaging(bool enable) {
    bool success = false;

    switch (current_architecture) {
    case ARCH_x86_64:
        break;
    case ARCH_arm64:
        break;
    default:
        break;
    }

    return success;
}
} // namespace arch