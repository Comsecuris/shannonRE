#!/bin/bash
# (C) Copyright 2015/2016 Comsecuris UG
# this script relies on busybox being present

CBD_PATH="/sbin/cbd"
DATA_DIR="/data/local/tmp"
LOG_DIR="/sdcard/log/"

function ADB {
    adb wait-for-device
    adb shell "su -c $1" | tr -d '\r'
}

CBD_PID=$(ADB "pidof cbd")
RADIO_PATH=$(ADB "find /dev/block/platform -name RADIO" | sed "s|^\/dev\/block||")
ADB "mkdir $LOG_DIR" > /dev/null
ADB "mkdir $DATA_DIR" > /dev/null

echo "[+] killing cbd ($CBD_PID)"
ADB "cp $CBD_PATH $DATA_DIR"
ADB "mount -o remount,rw /"
ADB "rm $CBD_PATH"
ADB "kill $CBD_PID"

echo "[+] replacing cbd"
ADB "chmod 770 $DATA_DIR/cbd"

echo "[+] triggering ramdump of $RADIO_PATH (wait for reboot, may take a while!)"

# NOTE: platform/15570000.ufs/by-name/RADIO here may be device specific
# NOTE: you may want to change that on different devices
ADB "$DATA_DIR/cbd -d -t ss333 -b s -m l -P platform/15570000.ufs/by-name/RADIO -o u"

echo "[+] waiting for device"
adb wait-for-device

# if we don't do the folllowing, for some reason we only pull some of the files
echo "[!] device back, giving it another 30 seconds"
sleep 30
adb wait-for-device

echo "[+] grabbing files"
adb pull $LOG_DIR
DUMP_DIR="$(date +"%Y-%M-%d-%s")"
mkdir $DUMP_DIR

echo "[+] wiping sdcard log"
ADB "rm $LOG_DIR/*"
mv *.log $DUMP_DIR

echo "[!] done, find your files in $DUMP_DIR"



