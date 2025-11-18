set -e

if [ "$1" == "arm64e" ]; then
	sudo nvram boot-args="debug=0x100 keepsyms=1 amfi_get_out_of_my_way=1 amfi_allow_any_signature=1 --arm64e_preview_abi"
elif [ "$1" == "x86_64" ]; then
	sudo nvram boot-args="debug=0x100 keepsyms=1 amfi_get_out_of_my_way=1 amfi_allow_any_signature=1"
else
	echo Bad Architecture $1
	exit 1
fi

if [ -d "DarwinKit.kext" ]; then
	sudo rm -R DarwinKit.kext
fi

bazel clean

sudo /usr/bin/kmutil install --volume-root /

bazel build --macos_cpus $1 :DarwinKit

unzip bazel-bin/DarwinKit.zip

$(xcrun --sdk macosx --find dsymutil) DarwinKit.kext/Contents/MacOS/DarwinKit

sudo chmod -R 755 DarwinKit.kext
sudo chown -R root:wheel DarwinKit.kext

sudo kextload -v DarwinKit.kext
