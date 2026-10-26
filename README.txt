Source of the patched mpr555*/mpr565* DLLs (the palette limit fix).

It is a binary patcher, not C source: the original rasterizer DLLs are not rebuilt, they are
rewritten by palgrow.py (see its header comment for the full explanation).

  pip install pefile capstone
  python3 palgrow.py ORIGINAL_mpr555.dll PATCHED_mpr555.dll [records, default 1024]

Run it once per DLL (all 8: mpr555, mpr555m, mpr555p, mpr555pm, mpr565, mpr565m, mpr565p, mpr565pm)
on the ORIGINAL game DLLs. The patched DLLs go into the patcher jar under dll/.

rig.py / exetest.py (+ shipmodels.py) are the emulator test harnesses used to check the result (need unicorn);
they are not needed to build.
