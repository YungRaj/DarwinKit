#pragma once

#include <Foundation/Foundation.h>
#include <DiskArbitration/DiskArbitration.h>

extern "C" {
int MountPartition(NSString *bsdDeviceName);
int MountDmg(NSString *path);
}
