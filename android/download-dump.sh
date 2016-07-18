#!/bin/bash
# © Copyright 2015/2016 Comsecuris UG
# NOTE: this script relies on busybox being present
# NOTE: also this script assumes that based on the call event a crash will
# NOTE: happen. if you just want to use it to pull a ramdump
# NOTE: use *#9090# in the dialer and use force cp crashdump.
# NOTE: lastly, the script assumes IDA is installed and calls idaq at the end.
# NOTE: what you should see is:
# bash download-dump.sh
# [+] cleaning old dumps
# [!] now run your exploit
# [+] toggling airplane mode
# Broadcasting: Intent { act=android.intent.action.AIRPLANE_MODE (has extras) }
# Broadcast completed: result=0
# Broadcasting: Intent { act=android.intent.action.AIRPLANE_MODE (has extras) }
# Broadcast completed: result=0
# [+] found crash dump...
# [!] waiting for file to grow
# ...
# 5862 KB/s (134656256 bytes in 22.429s)
# [!] done cpcrash_dump_20160629-1255.log
# [!] crash information:
# UMTS: pal_PlatformMisc.c
# Fatal error: PAL_MISC_CRASH_BY_AP

LOG_DIR="/sdcard/log/"

function ADB {
    adb wait-for-device
    adb shell "$1" | tr -d '\r'
}

function activate_display {
    adb shell dumpsys power | grep "Display Power: state=ON" > /dev/null
    if [ ! $? -eq 0 ]; then
        echo "switching on display"
        # power
        ADB "input keyevent 26"
    fi
}

function unlock {
    activate_display
    # unlock
    sleep 1
    ADB "input swipe 1 1400 1300 1400"
    sleep 1
}

function enable_ramdumps {
    # dialer
    adb shell "am start tel:" > /dev/null
    # enable ramdumps
    # by enabling menu and selecting
    # the following seems unreliable, not sure why
    sleep 1
    ADB "input keyevent 17"
    ADB "input keyevent 18"
    ADB "input keyevent 16"
    ADB "input keyevent 7"
    ADB "input keyevent 16"
    ADB "input keyevent 7"
    ADB "input keyevent 18"

    # not sure why this is needed, but somehow the number is eaten
    # up and i have to do it again
    #ADB "input keyevent 17"
    #ADB "input keyevent 18"
    #ADB "input keyevent 16"
    #ADB "input keyevent 7"
    #ADB "input keyevent 16"
    #ADB "input keyevent 7"
    #ADB "input keyevent 18"

    sleep 2
    ADB "input tap 987 500" # enable ramdump

    adb shell "am start tel:1338" > /dev/null # dial victim
    ADB "input tap 700 2383" # enable ramdump
}

function toggle_airplane {
    echo "[+] toggling airplane mode"

    adb shell "settings put global airplane_mode_on 1"
    adb shell "am broadcast -a android.intent.action.AIRPLANE_MODE --ez state true"
    sleep 3
    adb shell "settings put global airplane_mode_on 0"
    adb shell "am broadcast -a android.intent.action.AIRPLANE_MODE --ez state false"
}

ADB "mkdir $LOG_DIR" > /dev/null

echo "[+] cleaning old dumps"
ADB "rm -f $LOG_DIR/*"

echo "[!] now run your exploit"

unlock
toggle_airplane

sleep 3

enable_ramdumps

while true; do
    OUT="$(ADB "ls -l $LOG_DIR/cpcrash_dump*")"
    echo $OUT | grep "No such" > /dev/null
    if [ $? -eq 0 ]; then
        sleep 1
        continue
    fi
    echo "[+] found crash dump... "

    SIZE="$(ADB "ls -l /sdcard/log/cpcrash_dump*" | head -1 | sed -E 's,.*sdcard_r(w)* *([0-9]+) .*,\2,g')"
    # this is a silly heuristic. we just wait for the file to reach a reasonable size
    # and start copying the file. by the time adb pull is about to complete, the file is complete so we don't
    # need to know an exact size here. the reason we start early with copying is that we want to be done before
    # the phone goes into the crash screen/state so we get the log before we reboot the device.
    if [ ! $SIZE -gt 100000000 ] ; then
        echo "[!] waiting for file to grow"
        sleep 1
        continue
    fi

    FILE="$(ADB "ls -l /sdcard/log/cpcrash_dump*" | head -1 | sed -E 's,.*(cpcrash_dump.*),\1,g')"

    echo "[+] copying from the phone"
    adb wait-for-device
    adb pull "$LOG_DIR/$FILE"
    break
done

echo "[!] done $FILE"
echo "[!] crash information:"
ADB "cat $LOG_DIR/*s33*"
echo ""

idaq "$FILE"
