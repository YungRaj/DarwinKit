# DarwinKit
DarwinKit is a tool for macOS that tears apart most of the security features that normally would
protect your machine.

This project is also designed to be a great example of using [Google's build system](https://github.com/bazelbuild/bazel) in bazel, Google's Testing and Fuzzing Infrastructure via [googletest](https://github.com/google/googletest) and [googlefuzztest](https://github.com/google/fuzztest), and additional fuzzing infra in [LibAFL](https://github.com/AFLplusplus/LibAFL). It is intended to be a marriage of the best of both the Apple and Google ecosystem.

DarwinKit is your Swiss Army knife for macOS. It assists with reverse engineering, static and dynamic analysis as well as fuzzing production code in the macOS kernel and userspace. It works on both
x86_64 and arm64 machines.

Fuzzers for macOS are in progress, but aren't complete.

## Getting Started
### Install bazel
```
https://bazel.build/install/os-x
```
### Install Xcode
Please install [Xcode](https://developer.apple.com/xcode/). If you get any errors in bazel related to not having Xcode, please install Xcode and then run.
```
bazel clean --expunge 
sudo xcode-select -s /Applications/Xcode.app/Contents/Developer
sudo xcodebuild -license
bazel clean --expunge
```
### Building the kext
```sh
bazel build --macos_cpus=arm64 :DarwinKit
```
or
```sh
bazel build --macos_cpus=x86_64 :DarwinKit
```
### Running the kext
```sh
./load_kext.sh
```
### Build the userspace command line tool
```sh
bazel build --macos_cpus=arm64 :DarwinKit_inject
```
or
```sh
bazel build --macos_cpus=x86_64 :DarwinKit_inject
```
### Building the userspace tooling (as a library)
```sh
bazel build --macos_cpus=arm64 :DarwinKit_user
```
or
```sh
bazel build --macos_cpus=x86_64 :DarwinKit_user
```
### Other targets
DarwinKit contains other build targets that might be useful. Simply search through the `BUILD` file to
examine any targets you're interested in and build them with
```sh
bazel build :target
```

## Overview
Within DarwinKit, there is a kext and userspace portion. Both portions share a fraction of their codebase in the `darwinkit` folder.

The kext portion runs as a kernel extension. The kext code is present in the `kernel` folder.

The userspace portion can either be built as a static library or command line tool. The code for both is in the `user` folder.

    .
    ├── arm64/
    ├── x86_64/
    ├── darwinkit/
    ├── kernel/
    │   ├── start.cc
    └── user/
        ├── main.cc

## Features
###  Kext
- Symbolicating the XNU Kernel and all loaded kexts in the `KernelCache`/`KernelCollection`
- Parse MachOs of all kinds in Kernels/Kexts/etc
- Read/Write/Allocate/Deallocate/Map/Remap/Protect Virtual Memory
- Read/Write Physical Memory
- Parse Debug Symbols in the `KDK` Kernels
- Patch Kernel `__TEXT` and all other Segments/Sections
- Hooking Functions in the Kernel
- Traverse PCI configuration space
- Loading Plugins that perform hooks
- A coverage engine for all kernel + kext code (in progress)
- GDB Stub for debugging the kernel (in progress)
### Userspace
- Injecting Libraries into processes using ROP/JOP and `dlopen()` from a remote process
- Parsing all symbols of loaded libraries including libraries present in the dyld shared cache
- Dumping shared cache libraries and rebuilding the `strtab` and `symtabs`. You can open these in IDA
- Parse MachOs of all kinds Kernels/Kexts/KernelCache/Dyld Shared Cache/etc
- Get a receive/send right to any remote process' task IPC port
- Parse Objective C and Swift segments in MachOs
- Running a fuzzer for binaries in userspace using Unicorn/Panda and Hypervisor.framework (In Progress)
- Using a mutation engine such as AFL to do emulation based fuzzing

### License
This project is under the GPL License. See the [LICENSE](https://github.com/YungRaj/DarwinKit/blob/main/LICENSE) file for the full license text.
