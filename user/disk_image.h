#pragma once

#include <Foundation/Foundation.h>
#include <DiskArbitration/DiskArbitration.h>

extern "C" {
void MountPartition(NSString *bsdDeviceName);
void MountDmg(NSString *path);
}
