# DarwinKit
DarwinKit is a tool for macOS that tears apart most of the security features that normally would
protect your machine.

This assists with reverse engineering, static and dynamic analysis as well as fuzzing. It works on both
x86_64 and arm64 machines.

Fuzzers for macOS are in progress, but aren't complete.

## Getting Started
### Installing bazel
```
https://bazel.build/install/os-x
```
### Building the kext
```sh
bazel build --macos_cpus=arm64 :DarwinKit
```
or
```sh
bazel build --macos_cpus=x86_64 :DarwinKit
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

### License
This project is under the GPL License. See the [LICENSE](https://github.com/YungRaj/DarwinKit/blob/main/LICENSE) file for the full license text.
