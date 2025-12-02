#include "fuzzer.h"

#include "kernel.h"
#include "disk_image.h"

#include <Foundation/Foundation.h>

int LLVMFuzzerTestOneInput(uint8_t* data, size_t size) {
    xnu::Kernel* kernel = xnu::Kernel::Xnu();
    // Only enable coverage during each test case
    kernel->EnableCoverage();
    // Start fuzzing here
    @autoreleasepool {
        // Creates NSData object from fuzzer input
        NSData *dmgData = [NSData dataWithBytes:data length:size];
        // Generates a temporary, unique file path for the DMG
        NSString *tempDir = NSTemporaryDirectory();
        NSString *fileName = [NSString stringWithFormat:@"fuzz-input-%d.dmg", getpid()];
        NSString *filePath = [tempDir stringByAppendingPathComponent:fileName];
        // Writes the input data to the temporary file
        NSError *error = nil;
        BOOL success = [dmgData writeToFile:filePath options:NSDataWritingAtomic error:&error];
        if (!success) {
            NSLog(@"Failed to write DMG file: %@, Error: %@", filePath, error);
            return 0; 
        }
        // Performs the DMG mount and attach operation
        // Attach and mount the dmg file contents
        MountDmg(filePath);
        // Cleans up the temporary file
        [[NSFileManager defaultManager] removeItemAtPath:filePath error:nil];
    }
    kernel->DisableCoverage();
}
