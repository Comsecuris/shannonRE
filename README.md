Helpful scripts for various tasks performed during reverse engineering the Shannon Baseband with the goal to exploit the Samsung Galaxy S6.
Specifically, this is the code release for [https://comsecuris.com/slides/recon2016-breaking_band.pdf](https://comsecuris.com/slides/recon2016-breaking_band.pdf)

Please reach out to us for patches or future research in this direction!

Structure of this repository:
```
├── 010
│   └── sam.bt [010 template for Shannon's TOC header format]
├── android
│   ├── collect-ramdump.sh [Collect ramdumps using cbd directly, requires root]
│   └── download-dump.sh [Collect ramdumps using the menu, does not require root]
├── idapython
│   ├── loader
│   │   └── sam_modem_ramdump.py [IDA loader for the Shannon MAIN image]
│   ├── misc
│   │   └── clean-IDC.sh [Clean up an IDC by removing {comments, filenames, *_something named labels, deletes}]
│   │   └── typeinfo.idc [Structure definitions for a Shannon idb]
│   └── plugins
│       ├── def_arm32_functions.py [Auto-find more functions by scanning for prologues]
│       ├── find_mcr.py [Find and label all the mcr instructions in an idb]
│       ├── label_functions.py [Label function names automatically using string references]
│       ├── name_msg_handlers.py [Name an L3 task's message handlers in its dispatch table automatically]
│       ├── parse_mpu.py [Parse the modem's MPU config table and pretty print all the configuration rules]
│       ├── pseudocomments.py [Save/Restore pseudocode comments from/to an idb. This is useful because IDCs lack these.]
│       ├── register_map.py [Label the register map inside a modem ramdump]
│       ├── stackscan.py [Identify possible stackframes inside a modem ramdump]
│       └── taskscan.py [Walk the task linked list in a modem ramdump to enumerate and label tasks]
└── modem
    ├── memdump.py [Dump memory ranges live from the modem]
    ├── readmem.py [Read memory from a modem address]
    ├── unpack_modem.py [Split up a modem image into its TOC parts (Boot, Main, etc)]
    └── writemem.py [Write memory to a modem address]
```
