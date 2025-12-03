#include "disk_image.h"

#include <Foundation/Foundation.h>
#include <DiskArbitration/DiskArbitration.h>

#define SWIFT_THROWS __attribute__((__swift_error__(nonnull_error)))

@interface DIDeviceHandle : NSObject
@property (nonnull, retain, nonatomic) NSString *BSDName;
@property (readonly, nonatomic) NSUInteger regEntryID;
@property (nonatomic) BOOL handleRefCount;
@end

NS_ASSUME_NONNULL_BEGIN
@interface DIAttachParams : NSObject
-(id)initWithURL:(NSURL * _Nonnull)arg1 error:(NSError ** _Nonnull)arg2 SWIFT_THROWS;
@end

@interface DiskImages2 : NSObject
+(BOOL)attachWithParams:(DIAttachParams *)param handle:(DIDeviceHandle * _Nullable * _Nullable)h error:(NSError **)err SWIFT_THROWS;
@end

NS_ASSUME_NONNULL_END

int MountPartition(NSString *bsdDeviceName) {
    // Creates a Disk Arbitration Session
    DASessionRef session = DASessionCreate(kCFAllocatorDefault);
    if (!session) {
        NSLog(@"[Partition Mount] Failed to create DA Session for %@", bsdDeviceName);
        return -1;
    }
    // Gets a DADiskRef from the BSD name (e.g., /dev/diskXs1)
    DADiskRef daDisk = DADiskCreateFromBSDName(kCFAllocatorDefault, session,
                                               [bsdDeviceName UTF8String]);
    if (!daDisk) {
        NSLog(@"[Partition Mount] Failed to create DADiskRef for %@", bsdDeviceName);
        CFRelease(session);
        return -1;
    }
    // Mounts the disk. DADiskMount is asynchronous and requires 5 arguments.
    // We pass NULL for the path, callback, and context to use default options and block implicitly.
    DADiskMount(daDisk, 
                NULL /* path (use default) */, 
                kDADiskMountOptionDefault, 
                NULL /* callback */, 
                NULL /* context */);
    NSLog(@"[Partition Mount] Attempted to mount partition: %@", bsdDeviceName);
    CFRelease(daDisk);
    CFRelease(session);
    return 0;
}

int MountDmg(NSString *path) {
    NSURL *dmgURL = [NSURL fileURLWithPath: path];
    NSError *error;
    DIAttachParams *params = [[DIAttachParams alloc] initWithURL: dmgURL error:&error];
    DIDeviceHandle *deviceAttached;
    [DiskImages2 attachWithParams: params handle: &deviceAttached error: nil];
    if (deviceAttached) {
        int result = 0;
        NSString *parentBSDName = [deviceAttached BSDName];
        printf("Attached dmg, Parent BSD Name: %s\n", [parentBSDName UTF8String]);
        // Finds partitions using DADiskCopyWholeDisk's description
        DASessionRef lookupSession = DASessionCreate(kCFAllocatorDefault);
        DADiskRef wholeDisk = DADiskCreateFromBSDName(kCFAllocatorDefault, lookupSession, [parentBSDName UTF8String]);
        if (wholeDisk) {
            // Gets the whole disk's description dictionary
            CFDictionaryRef diskDescription = DADiskCopyDescription(wholeDisk);
            // Gets the list of partitions (slices)
            CFArrayRef wholeDiskPartitions = (CFArrayRef) CFDictionaryGetValue(diskDescription, kDADiskDescriptionMediaContentKey);
            if (wholeDiskPartitions) {
                // Iterate over the partitions and mount them
                for (id partition in (__bridge NSArray *)wholeDiskPartitions) {
                    NSString *bsdName = partition[@"DADeviceBSDName"];
                    if (bsdName) {
                        result = MountPartition(bsdName);
                        if (result != 0) {
                            return result;
                        }
                    }
                }
            } else {
                NSLog(@"Could not find partitions array in disk description.");
                return -1;
            }
            CFRelease(diskDescription);
            CFRelease(wholeDisk);
        } else {
            result = -1;
        }
        CFRelease(lookupSession);
        return result;
    } else {
        fprintf(stderr, "couldn't attach DMG or get device handle\n");
        return -1;
    }
}
