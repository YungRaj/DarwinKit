load("@rules_apple//apple:ios.bzl", "ios_static_framework")
load("@rules_apple//apple:macos.bzl", "macos_command_line_application", "macos_dynamic_framework", "macos_kernel_extension")

config_setting(
    name = "arm64",
    values = {
        "macos_cpus": "arm64",
    },
)

config_setting(
    name = "arm64e",
    values = {
        "macos_cpus": "arm64e",
    },
)

config_setting(
    name = "x86_64",
    values = {"macos_cpus": "x86_64"},
)

cc_library(
    name = "darwinkit_test",
    hdrs = glob(["darwinkit/*.h"]),
    copts = ["-fsanitize=address"],
    includes = [
        "darwinkit",
    ],
)

cc_test(
    name = "macho_test",
    srcs = [
        "darwinkit/macho.cc",
        "darwinkit/symbol_table.cc",
        "tests/macho_test.cc",
    ],
    copts = [
        "-w",
        "-std=c++20",
        "-D__USER__",
        "-I./",
        "-I./capstone/include",
        "-DCAPSTONE_HAS_X86",
        "-DCAPSTONE_HAS_ARM64",
    ],
    data = glob(["tests/testdata/*"]),
    deps = [
        ":darwinkit_test",
        "@fuzztest//fuzztest",
        "@fuzztest//fuzztest:fuzztest_gtest_main",
        "@googletest//:gtest",
    ],
)

genrule(
    name = "capstone_universal_lib",
    srcs = ["capstone"],
    outs = ["libcapstone_universal.a"],
    cmd = """
        cd capstone
        export ARCH=x86_64
        export SDKROOT=$$(xcrun --sdk macosx --show-sdk-path)
        export CC="$$(xcrun --sdk macosx --find clang)"
        export CXX="$$(xcrun --sdk macosx --find clang++)"
        export CFLAGS="-isysroot $$SDKROOT -target $$ARCH-apple-macos"
        export CXXFLAGS="$$CFLAGS"
        export LDFLAGS="-isysroot $$SDKROOT -target $$ARCH-apple-macos"
        make clean
        export CAPSTONE_ARCHS="x86 aarch64"
        ./make.sh mac-universal-no
        cd ..
        cp capstone/libcapstone.a libcapstone_x86_64_universal.a
        cd capstone
        export ARCH=arm64
        export SDKROOT=$$(xcrun --sdk macosx --show-sdk-path)
        export CC="$$(xcrun --sdk macosx --find clang)"
        export CXX="$$(xcrun --sdk macosx --find clang++)"
        export CFLAGS="-isysroot $$SDKROOT -target $$ARCH-apple-macos"
        export CXXFLAGS="$$CFLAGS"
        export LDFLAGS="-isysroot $$SDKROOT -target $$ARCH-apple-macos"
        make clean
        export CAPSTONE_ARCHS="x86 aarch64"
        ./make.sh mac-universal-no
        cd ..
        cp capstone/libcapstone.a libcapstone_arm64_universal.a
        lipo -create -output $(OUTS) libcapstone_arm64_universal.a libcapstone_x86_64_universal.a
    """,
    tags = ["no-sandbox"],
)

cc_library(
    name = "capstone_fat_static_universal",
    srcs = [":capstone_universal_lib"],
    hdrs = [],
    linkstatic = True,
    alwayslink = True,
)

genrule(
    name = "capstone_fat_kernel",
    srcs = ["capstone"],
    outs = ["libcapstone_osx_kernel_fat.a"],
    cmd = """
        cd capstone
        export ARCH=x86_64
        export SDKROOT=$$(xcrun --sdk macosx --show-sdk-path)
        export CC="$$(xcrun --sdk macosx --find clang)"
        export CXX="$$(xcrun --sdk macosx --find clang++)"
        export CFLAGS="-isysroot $$SDKROOT -target $$ARCH-apple-macos"
        export CXXFLAGS="$$CFLAGS"
        export LDFLAGS="-isysroot $$SDKROOT -target $$ARCH-apple-macos"
        make clean
        ./make.sh osx-kernel clean
        export CAPSTONE_ARCHS="x86 aarch64"
        echo "Building for ARCH=$$ARCH"
        ./make.sh osx-kernel
        cd ..
        mv capstone/libcapstone.a libcapstone_osx_kernel_x86_64.a
        cd capstone
        export ARCH=arm64e
        export SDKROOT=$$(xcrun --sdk macosx --show-sdk-path)
        export CC="$$(xcrun --sdk macosx --find clang)"
        export CXX="$$(xcrun --sdk macosx --find clang++)"
        export CFLAGS="-isysroot $$SDKROOT -target $$ARCH-apple-macos"
        export CXXFLAGS="$$CFLAGS"
        export LDFLAGS="-isysroot $$SDKROOT -target $$ARCH-apple-macos"
        make clean
        ./make.sh osx-kernel clean
        export CAPSTONE_ARCHS="x86 aarch64"
        echo "Building for ARCH=$$ARCH"
        ./make.sh osx-kernel
        cd ..
        cp capstone/libcapstone.a libcapstone_osx_kernel_arm64.a
        lipo -create -output $(OUTS) libcapstone_osx_kernel_x86_64.a libcapstone_osx_kernel_arm64.a
    """,
    tags = ["no-sandbox"],
)

cc_library(
    name = "capstone_fat_static_kernel",
    srcs = [":capstone_fat_kernel"],
    hdrs = [],
    linkstatic = True,
    alwayslink = True,
)

cc_library(
    name = "DarwinKit_user_iokit",
    srcs = glob(["user/*.c"]),
    hdrs = glob(["user/*.h"]) + glob(["darwinkit/*.h"]),
    copts = [
        "-w",
        "-D__USER__",
        "-I./",
        "-I./capstone/include",
        "-DCAPSTONE_HAS_X86",
        "-DCAPSTONE_HAS_ARM64",
    ],
    includes = [
        "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include",
        "/usr/include",
        "/usr/local/include",
        "darwinkit",
        "user",
    ],
    linkopts = [
        "-framework",
        "IOKit",
    ],
    linkstatic = True,
    visibility = ["//visibility:public"],
    deps = [],
    alwayslink = True,
)

cc_library(
    name = "DarwinKit_user",
    srcs = glob(["user/*.cc"]) + glob([
        "darwinkit/*.cc",
    ]) + select({
        ":arm64": glob(
            [
                "arm64/*.s",
            ],
            allow_empty = True,
        ),
        ":arm64e": glob(
            [
                "arm64/*.s",
            ],
            allow_empty = True,
        ),
        ":x86_64": glob(
            [
                # "x86_64/*.s"
            ],
            allow_empty = True,
        ),
    }) + glob([
        "arm64/*.cc",
    ]) + glob([
        "x86_64/*.cc",
    ]),
    hdrs = glob(["user/*.h"]) + glob(["darwinkit/*.h"]) + glob(["arm64/*.h"]) + glob(["x86_64/*.h"]) + glob(["capstone/include/capstone/*.h"]),
    copts = [
        "-w",
        "-std=c++20",
        "-D__USER__",
        "-I./",
        "-I./capstone/include",
        "-DCAPSTONE_HAS_X86",
        "-DCAPSTONE_HAS_ARM64",
        "-iframework",
        "/System/Library/PrivateFrameworks",
    ],
    includes = [
        "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include",
        "/usr/include",
        "/usr/local/include",
        "darwinkit",
        "user",
    ],
    linkopts = [
        "-framework",
        "IOKit",
        "-lEndpointSecurity",
        "-lbsm",
    ],
    visibility = ["//visibility:public"],
    deps = [":DarwinKit_user_iokit"],
    alwayslink = True,
)

objc_library(
    name = "DarwinKit_LLVMFuzzer",
    srcs = glob(["user/*.mm"]),
    hdrs = glob(["user/*.h"]) + glob(["darwinkit/*.h"]),
    copts = [
        "-w",
        "-std=c++20",
        "-D__USER__",
        "-I./",
        "-I./capstone/include",
        "-DCAPSTONE_HAS_X86",
        "-DCAPSTONE_HAS_ARM64",
    ],
    includes = [
        "darwinkit",
        "user",
    ],
    visibility = ["//visibility:public"],
    alwayslink = True,
)

cc_shared_library(
    name = "DarwinKitTool_fuzzer",
    additional_linker_inputs = [
        ":DarwinKit_LLVMFuzzer",
    ],
    user_link_flags = [
        "-framework",
        "Hypervisor",
        "-iframework",
        "/System/Library/PrivateFrameworks",
        "-framework",
        "DiskImages2",
        "-framework",
        "DiskArbitration",
        "$(location :DarwinKit_LLVMFuzzer)",
    ],
    visibility = ["//visibility:public"],
    deps = [
        ":DarwinKit_user",
        ":capstone_fat_static_universal",
    ],
)

cc_library(
    name = "DarwinKitTool_main",
    srcs = ["main.cc"],
    hdrs = glob(["user/*.h"]) + glob(["darwinkit/*.h"]),
    additional_linker_inputs = [
        ":DarwinKitTool_fuzzer",
    ],
    includes = [
        "darwinkit",
        "user",
    ],
    linkopts = [
        "-lresolv",
        "$(location :DarwinKitTool_fuzzer)",
        "-Wl,-rpath,@executable_path/",
    ],
    visibility = ["//visibility:public"],
    deps = [
        ":libafl_fuzzer_frida",
    ],
)

macos_command_line_application(
    name = "darwinkit_tool",
    additional_linker_inputs = [
        ":DarwinKitTool_fuzzer",
    ],
    codesignopts = [
        "--entitlements",
        "entitlements.xml",
    ],
    linkopts = [
        "$(location :DarwinKitTool_fuzzer)",
    ],
    minimum_os_version = "11.0",
    deps = [
        ":DarwinKitTool_main",
    ],
)

objc_library(
    name = "cycript_runner",
    srcs = ["user/lib/cycript_runner.mm"],
    hdrs = [],
    linkopts = [
        "-framework",
        "AppKit",
        "-framework",
        "Foundation",
    ],
    alwayslink = True,
)

cc_binary(
    name = "cycript_runner_lib",
    linkshared = True,
    deps = [
        ":cycript_runner",
    ],
)

genrule(
    name = "libcycript_runner",
    srcs = [":cycript_runner_lib"],
    outs = ["libcycript_runner.dylib"],
    cmd = """
        cp $(SRCS) $(OUTS)
        codesign -fs - --deep --entitlements entitlements.xml $(OUTS)
    """,
    tags = ["no-sandbox"],
)

cc_library(
    name = "DarwinKit_kext_library",
    srcs = glob(["kernel/*.c"] + ["darwinkit/*.c"]),
    hdrs = glob(["kernel/*.h"]) + glob(["darwinkit/*.h"]),
    copts = [
        "-w",
        "-mkernel",
        "-D__KERNEL__",
        "-nostdlib",
        "-I./",
        "-I./capstone/include",
        "-isystem",
        "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/System/Library/Frameworks/Kernel.framework/Headers",
        "-isystem",
        "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/System/Library/Frameworks/IOKit.framework/Headers",
        "-DCAPSTONE_HAS_X86",
        "-DCAPSTONE_HAS_ARM64",
        "-DCAPSTONE_HAS_OSXKERNEL=1",
    ],
    includes = [
        "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include",
        "/usr/include",
        "/usr/local/include",
        "darwinkit",
        "kernel",
    ],
    linkopts = [
        "-framework",
        "IOKit",
        "-Wl,-sectalign,__DATA,__cov,0x4000",
        "-Wl,-order_file,cov.order",
    ],
    visibility = ["//visibility:public"],
    alwayslink = True,
)

cc_library(
    name = "DarwinKit_kext",
    srcs = glob(["kernel/*.cc"]) + glob([
        "darwinkit/*.cc",
    ]) + select({
        ":arm64": glob(
            [
                "arm64/*.s",
            ],
            allow_empty = True,
        ),
        ":arm64e": glob(
            [
                "arm64/*.s",
            ],
            allow_empty = True,
        ),
        ":x86_64": glob(
            [
                # "x86_64/*.s"
            ],
            allow_empty = True,
        ),
        "//conditions:default": glob([
            "arm64/*.s",
        ]),
    }) + glob([
        "arm64/*.cc",
    ]) + glob([
        "x86_64/*.cc",
    ]),
    hdrs = glob(["kernel/*.h"]) + glob(["darwinkit/*.h"]) + glob(["arm64/*.h"]) + glob(["x86_64/*.h"]) + glob(["capstone/include/capstone/*.h"]),
    copts = [
        "-w",
        "-Xlinker",
        "-kext",
        "-Xlinker",
        "-export_dynamic",
        "-Wl,-kext",
        "-lkmod",
        "-lkmodc++",
        "-lcc_kext",
        "-std=c++20",
        "-mkernel",
        "-D__KERNEL__",
        "-nostdlib",
        "-I./",
        "-I./capstone/include",
        "-isystem",
        "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/System/Library/Frameworks/Kernel.framework/Headers",
        "-isystem",
        "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/System/Library/Frameworks/IOKit.framework/Headers",
        "-DCAPSTONE_HAS_X86",
        "-DCAPSTONE_HAS_ARM64",
        "-DCAPSTONE_HAS_OSXKERNEL=1",
    ],
    includes = [
        "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include",
        "/usr/include",
        "/usr/local/include",
        "darwinkit",
        "kernel",
    ],
    linkopts = [
        "-framework",
        "IOKit",
    ],
    visibility = ["//visibility:public"],
    deps = [
        ":DarwinKit_kext_library",
        ":capstone_fat_static_kernel",
        ":libafl_fuzzer_no_std",
    ],
    alwayslink = True,
)

genrule(
    name = "libafl_fuzzer_no_std_genrule",
    srcs = [
        "fuzz/kernel/libafl_fuzzer.rs",
        "fuzz/kernel/allocator.rs",
        "fuzz/kernel/Cargo.toml",
        "fuzz/kernel/arm64e-kernel.json",
        "fuzz/kernel/x86_64-kernel.json",
    ],
    outs = ["liblibafl_fuzzer_no_std_lib.a"],
    cmd = """  
        export RUSTUP_TOOLCHAIN=nightly
        export RUSTFLAGS="-C panic=abort"
        rustup default nightly
	    rustup target add aarch64-apple-darwin
        rustup component add rust-src --toolchain nightly-aarch64-apple-darwin
        rustup install nightly-aarch64-apple-darwin --force-non-host
        rustup run nightly-aarch64-apple-darwin cargo build -Zbuild-std=core,alloc --target fuzz/kernel/arm64e-kernel.json --manifest-path fuzz/kernel/Cargo.toml -v
        cp target/arm64e-kernel/debug/liblibafl_fuzzer_no_std_lib.a libafl_libfuzzer_arm64e.a
        mkdir -p tmp
        cd tmp
        llvm-ar x ../libafl_libfuzzer_arm64e.a
        ar rcs ../liblibafl_fuzzer_no_std_lib_arm64e.a *.o
        cd ..
        rm -R tmp
        rustup target add x86_64-apple-darwin
        rustup component add rust-src --toolchain nightly-x86_64-apple-darwin
        rustup install nightly-x86_64-apple-darwin --force-non-host
        cargo build --target x86_64-apple-darwin -Zbuild-std=core,alloc --manifest-path fuzz/kernel/Cargo.toml -v
        cp target/x86_64-apple-darwin/debug/liblibafl_fuzzer_no_std_lib.a libafl_libfuzzer_x86_64.a
        mkdir -p tmp
        cd tmp
        llvm-ar x ../libafl_libfuzzer_x86_64.a
        ar rcs ../liblibafl_fuzzer_no_std_lib_x86_64.a *.o
        cd ..
        rm -R tmp
        lipo -create -output $(OUTS) liblibafl_fuzzer_no_std_lib_x86_64.a liblibafl_fuzzer_no_std_lib_arm64e.a
    """,
    tags = ["no-sandbox"],
)

genrule(
    name = "libafl_fuzzer_frida_genrule",
    srcs = [
        "fuzz/user/libafl_fuzzer.rs",
        "fuzz/user/Cargo.toml",
    ],
    outs = ["liblibafl_fuzzer_frida_lib.a"],
    cmd = """  
        export SDKROOT=$$(xcrun --sdk macosx --show-sdk-path)
        export RUSTUP_TOOLCHAIN=nightly
        rustup default nightly
        rustup target add aarch64-apple-darwin
        rustup component add rust-src --toolchain nightly-aarch64-apple-darwin
        rustup install nightly-aarch64-apple-darwin --force-non-host
        rustup run nightly-aarch64-apple-darwin cargo build --target aarch64-apple-darwin --manifest-path fuzz/user/Cargo.toml -v
        cp target/aarch64-apple-darwin/debug/liblibafl_fuzzer_frida_lib.a $(OUTS)
        # cp target/aarch64-apple-darwin/debug/liblibafl_fuzzer_frida_lib.a liblibafl_fuzzer_frida_lib_arm64.a
        # rustup target add x86_64-apple-darwin
        # rustup component add rust-src --toolchain nightly-x86_64-apple-darwin
        # rustup install nightly-x86_64-apple-darwin --force-non-host
        # cargo build --target x86_64-apple-darwin --manifest-path fuzz/user/Cargo.toml -v
        # cp target/x86_64-apple-darwin/debug/liblibafl_fuzzer_frida_lib.a liblibafl_fuzzer_frida_lib_x86_64.a
        # lipo -create -output $(OUTS) liblibafl_fuzzer_frida_lib_x86_64.a liblibafl_fuzzer_frida_lib_arm64.a
    """,
    tags = ["no-sandbox"],
)

cc_library(
    name = "libafl_fuzzer_no_std",
    srcs = [":libafl_fuzzer_no_std_genrule"],
    linkstatic = True,
    alwayslink = True,
)

cc_library(
    name = "libafl_fuzzer_frida",
    srcs = [":libafl_fuzzer_frida_genrule"],
    alwayslink = True,
)

macos_kernel_extension(
    name = "DarwinKit",
    additional_contents = {},
    additional_linker_inputs = [],
    bundle_id = "com.YungRaj.DarwinKit",
    bundle_id_suffix = "_",
    bundle_name = "DarwinKit",
    codesign_inputs = [],
    entitlements = "entitlements.xml",
    entitlements_validation = "loose",
    executable_name = "DarwinKit",
    exported_symbols_lists = [],
    families = ["mac"],
    infoplists = ["Info.plist"],
    ipa_post_processor = None,
    linkopts = [
        "-framework",
        "IOKit",
        "-kext",
        "-export_dynamic",
        "-lkmod",
        "-lkmodc++",
    ],
    minimum_deployment_os_version = "",
    minimum_os_version = "11.0",
    platform_type = "macos",
    provisioning_profile = None,
    resources = [],
    shared_capabilities = [],
    stamp = 1,
    strings = [],
    version = None,
    deps =
        [":DarwinKit_kext"],
)

objc_library(
    name = "Crawler_static",
    srcs = glob(["user/FakeTouch/*.mm"]) + glob(["user/lib/crawler.mm"]),
    hdrs = glob(["user/FakeTouch/*.h"]) + glob(["user/lib/crawler.h"]),
    alwayslink = True,
)

ios_static_framework(
    name = "Crawler",
    hdrs = [],
    bundle_name = "Crawler",
    families = [
        "iphone",
        "ipad",
    ],
    minimum_os_version = "13.0",
    deps = [
        ":Crawler_static",
    ],
)
