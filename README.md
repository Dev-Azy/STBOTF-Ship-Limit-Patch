# STBOTF-Ship-Limit-Patch
Star Trek - Birth of the Federation: Ship limit patcher

What this patch does:
1 Increase ship models to 512
2 Increase palette size to 1023

The warning dialog then lists what will be replaced: trek.exe and the 8 mpr555*/mpr565* DLLs. It has Proceed and Cancel buttons, and Cancel is the default.

- Backups: Each file is saved next to the original as NAME.bak, for example trek.exe.bak. If a .bak already exists, it is kept. A second run therefore won’t overwrite your first original.
- Replacing in place: trek.exe is patched with room for 512 ship models, and the 8 patched DLLs are copied over the old ones.
- Already patched exe: If the .mdl section is already there, the exe is left alone and only the DLLs are refreshed.
- Temp files: Everything is prepared in temp files first, and the game files are only touched once that has succeeded. The temp files are deleted afterwards. If the exe isn’t a stock 1.0.3, 
  the patch fails before anything is changed.

The old command-line form with an output file (trek.exe out.exe [capacity]) still writes a new exe only, for scripting.