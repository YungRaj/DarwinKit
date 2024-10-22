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

#include "plugin.h"

using namespace darwin;

Plugin::Plugin(IOService* service, char* product, Size version, UInt32 runmode,
               const char** disableArg, Size disableArgNum, const char** debugArg, Size debugArgNum,
               const char** betaArg, Size betaArgNum)
    : service(service), product(product), version(version), runmode(runmode),
      disableArg(disableArg), disableArgNum(disableArgNum), debugArg(debugArg),
      debugArgNum(debugArgNum), betaArg(betaArg), betaArgNum(betaArgNum) {}

Plugin::Plugin(char* product, Size version, UInt32 runmode, const char** disableArg,
               Size disableArgNum, const char** debugArg, Size debugArgNum, const char** betaArg,
               Size betaArgNum)
    : service(nullptr), product(product), version(version), runmode(runmode), disableArg(disableArg),
      disableArgNum(disableArgNum), debugArg(debugArg), debugArgNum(debugArgNum), betaArg(betaArg),
      betaArgNum(betaArgNum) {}