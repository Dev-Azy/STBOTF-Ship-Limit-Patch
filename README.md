# STBotF-Ship-Limit-Patch
Star Trek - Birth of the Federation: Ship limit patcher

What this patch does:
1 Increase ship models to 512
2 Increase maximum number of palettes to 1023

The warning dialog then lists what will be replaced: trek.exe and the 8 mpr555*/mpr565* DLLs. It has Proceed and Cancel buttons, and Cancel is the default.

- Backups: Each file is saved next to the original as NAME.bak, for example trek.exe.bak. If a .bak already exists, it is kept. A second run therefore won’t overwrite your first original.
- Replacing in place: trek.exe is patched with room for 512 ship models, and the 8 patched DLLs are copied over the old ones.
- Already patched exe: If the .mdl section is already there, the exe is left alone and only the DLLs are refreshed.
- Temp files: Everything is prepared in temp files first, and the game files are only touched once that has succeeded. The temp files are deleted afterwards. If the exe isn’t a stock 1.0.3, 
  the patch fails before anything is changed.

The old command-line form with an output file (trek.exe out.exe [capacity]) still writes a new exe only, for scripting.

1. Increase of ship models from 74 to 512

 Moves the ship model table of a (possibly already modded) BotF trek.exe into its own PE section ".mdl"
 and raises the number of ship models from 73 (+TMP) to 512 (+TMP).
 
 All current table contents (including your edits) are carried over. Everything else in the exe stays as is,
 except 3 code sites of the ship model lookup routine, which are checked before anything is changed.

 Details:

 ENTRY = 0x30;
 OLD_TABLE = 0x5919FCL, OLD_TMP = 0x5927ACL;
 OLD_COUNT = 73;
 SITE_BASE = 0x4A28AEL, SITE_TMP = 0x4A2881L, SITE_LOOP = 0x4A28C6L;
 LOOP_BACK = 0x4A28B9L, LOOP_EXIT = 0x4A28CFL;
 CODE_SIZE = 21;


 2. Increase maximum number of palettes from 129 to 1023

 Modified mpr*.dll overwrite the ones in the target directory. 
 
 More details about the mpr*.dll files, can be found in the tools branch of this repository. 
 https://github.com/Dev-Azy/stbotf_ship_limit_patch/tree/tools
