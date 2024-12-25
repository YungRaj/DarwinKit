#!/bin/bash

launchctl stop com.apple.usbmuxd
killall usbfluxd
echo "Initializing USB connection..."
launchctl start com.apple.usbmuxd
/Applications/USBFlux.app/Contents/Resources/usbfluxd
sleep 1
echo "Gathering a list of USB devices..."
sleep 3
idevice_id
