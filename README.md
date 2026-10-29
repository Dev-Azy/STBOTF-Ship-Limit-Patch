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

  moves the ship model table of `trek.exe` (73 entries + TMP, 48 bytes each,
  VA `0x5919FC`) into a new section `.mdl` with 512 entries + TMP and a 21 byte code cave:
  
  - three code sites are checked against the original bytes first: VA `0x4A28AE` (`mov ecx, table`),
    `0x4A2880` (`mov eax, TMP`) and `0x4A28C6` (the loop `inc ebx; add ecx,30h; cmp ebx,49h; jb`)
  - the table and TMP addresses are rewritten, the loop jumps to the cave which compares against the new count
    and jumps back or out
  - unused slots are filled with name `FF FF FF FF`, so they never match

 2. Increase maximum number of palettes from 127 to 1023

   Modified mpr*.dll overwrite the ones in the target directory. 
   
   More details about the mpr*.dll files, can be found in the tools branch of this repository. 
   https://github.com/Dev-Azy/stbotf_ship_limit_patch/tree/tools

Apply it after any other exe edits. UE9.0.3dev5 reads the table from the `.mdl` section afterwards, not from
the old file offset.
