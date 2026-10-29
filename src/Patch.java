import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.util.Arrays;

/**
 * Moves the ship model table of a (possibly already modded) BotF trek.exe into its own PE section ".mdl"
 * and raises the number of ship models from 73 (+TMP) to 512 (+TMP).
 *
 * All current table contents (including your edits) are carried over. Everything else in the exe stays as is,
 * except 3 code sites of the ship model lookup routine, which are checked before anything is changed.
 *
 * Usage:  java -jar STBotF Ship Limit Patch.jar [trek.exe [output.exe [capacity]]]
 *         without arguments a file chooser opens.
 */
public class Patch {

  static final int ENTRY = 0x30;
  static final long OLD_TABLE = 0x5919FCL, OLD_TMP = 0x5927ACL;
  static final int OLD_COUNT = 73;
  static final long SITE_BASE = 0x4A28AEL, SITE_TMP = 0x4A2881L, SITE_LOOP = 0x4A28C6L;
  static final long LOOP_BACK = 0x4A28B9L, LOOP_EXIT = 0x4A28CFL;
  static final int CODE_SIZE = 21;

  static int align(int v, int a) { return (v + a - 1) / a * a; }

  static int u16(byte[] d, int o) { return (d[o] & 0xFF) | (d[o + 1] & 0xFF) << 8; }
  static long u32(byte[] d, int o) { return (u16(d, o) | (long) u16(d, o + 2) << 16) & 0xFFFFFFFFL; }
  static void w16(byte[] d, int o, int v) { d[o] = (byte) v; d[o + 1] = (byte) (v >> 8); }
  static void w32(byte[] d, int o, long v) { w16(d, o, (int) v); w16(d, o + 2, (int) (v >> 16)); }

  /** Result info text. */
  public static String patch(File in, File out, int capacity) throws IOException {
    byte[] d = Files.readAllBytes(in.toPath());
    if (capacity < 74 || capacity > 4000)
      throw new IOException("capacity must be 74..4000");
    if (d.length < 0x400 || d[0] != 'M' || d[1] != 'Z')
      throw new IOException("not a PE exe file");

    int pe = (int) u32(d, 0x3C);
    if (pe < 0 || pe + 0x100 > d.length || d[pe] != 'P' || d[pe + 1] != 'E')
      throw new IOException("not a PE exe file");
    int nsec = u16(d, pe + 6);
    int optSize = u16(d, pe + 20);
    int opt = pe + 24;
    if (u16(d, opt) != 0x10B)
      throw new IOException("not a 32 bit exe");
    long imageBase = u32(d, opt + 28);
    int sa = (int) u32(d, opt + 32), fa = (int) u32(d, opt + 36);
    int secTab = opt + optSize;

    long[] va = new long[nsec], vs = new long[nsec], rs = new long[nsec], rp = new long[nsec];
    int maxEnd = 0;
    for (int i = 0; i < nsec; ++i) {
      int o = secTab + i * 40;
      String name = new String(d, o, 8, "ISO-8859-1").replace("\0", "");
      if (name.equals(".mdl"))
        throw new IOException("This exe is already patched (section .mdl exists). Nothing to do.");
      vs[i] = u32(d, o + 8); va[i] = u32(d, o + 12); rs[i] = u32(d, o + 16); rp[i] = u32(d, o + 20);
      maxEnd = Math.max(maxEnd, (int) (va[i] + Math.max(vs[i], rs[i])));
    }
    for (int k = 0; k < 40; ++k) {
      if (d[secTab + nsec * 40 + k] != 0)
        throw new IOException("no room for another section header");
    }

    // code sites of the lookup routine must be the original ones
    byte[][] expect = {
      hex("b9fc195900"),        // mov ecx,table
      hex("b8ac275900"),        // mov eax,TMP
      hex("4383c13083fb4972ea") // inc ebx; add ecx,30h; cmp ebx,49h; jb
    };
    long[] sites = { SITE_BASE, SITE_TMP - 1, SITE_LOOP };
    String[] what = { "table address", "TMP address", "lookup loop" };
    int[] off = new int[3];
    for (int i = 0; i < 3; ++i) {
      off[i] = v2o(d, secTab, nsec, imageBase, sites[i]);
      if (off[i] < 0 || off[i] + expect[i].length > d.length
        || !Arrays.equals(Arrays.copyOfRange(d, off[i], off[i] + expect[i].length), expect[i]))
        throw new IOException("The ship model lookup code (" + what[i] + ", VA 0x"
          + Long.toHexString(sites[i]) + ") is not the original one. This exe was modified in that place"
          + " and can't be patched safely.");
    }

    int oTab = v2o(d, secTab, nsec, imageBase, OLD_TABLE);
    int oTmp = v2o(d, secTab, nsec, imageBase, OLD_TMP);
    if (oTab < 0 || oTmp < 0 || oTab + OLD_COUNT * ENTRY > d.length || oTmp + ENTRY > d.length)
      throw new IOException("ship model table not found in the file");

    int newRva = align(maxEnd, sa);
    int newOff = align(d.length, fa);
    long tabVa = imageBase + newRva;
    long tmpVa = tabVa + (long) capacity * ENTRY;
    long caveVa = (tmpVa + ENTRY + 15) & ~15L;

    ByteBuffer sec = ByteBuffer.allocate(align((int) (caveVa - tabVa) + CODE_SIZE, fa)).order(ByteOrder.LITTLE_ENDIAN);
    for (int i = 0; i < capacity; ++i) {
      if (i < OLD_COUNT) {
        sec.put(d, oTab + i * ENTRY, ENTRY);
      } else {
        sec.put(new byte[] { -1, -1, -1, -1 });
        sec.put(new byte[ENTRY - 4]);
      }
    }
    sec.put(d, oTmp, ENTRY);
    sec.position((int) (caveVa - tabVa));
    // cave: inc ebx; add ecx,30h; cmp ebx,capacity; jb LOOP_BACK; jmp LOOP_EXIT
    sec.put(hex("4383c13081fb")).putInt(capacity);
    sec.put((byte) 0x0F).put((byte) 0x82).putInt(0); // jb rel32, filled in below
    int vsize = (int) (caveVa - tabVa) + CODE_SIZE;
    int raw = sec.capacity();
    byte[] sb = sec.array();
    int c = (int) (caveVa - tabVa);
    w32(sb, c + 12, LOOP_BACK - (caveVa + 16));       // jb rel32, next instruction at cave+16
    sb[c + 16] = (byte) 0xE9;
    w32(sb, c + 17, LOOP_EXIT - (caveVa + 21));        // jmp rel32, next instruction at cave+21

    byte[] r = Arrays.copyOf(d, newOff + raw);
    // patch code
    w32(r, off[0] + 1, tabVa);
    w32(r, off[1] + 1, tmpVa);
    r[off[2]] = (byte) 0xE9;
    w32(r, off[2] + 1, caveVa - (SITE_LOOP + 5));
    for (int k = 5; k < 9; ++k)
      r[off[2] + k] = (byte) 0x90;
    // section data
    System.arraycopy(sb, 0, r, newOff, raw);
    // section header
    int h = secTab + nsec * 40;
    byte[] nm = ".mdl".getBytes("ISO-8859-1");
    System.arraycopy(nm, 0, r, h, nm.length);
    w32(r, h + 8, vsize);
    w32(r, h + 12, newRva);
    w32(r, h + 16, raw);
    w32(r, h + 20, newOff);
    w32(r, h + 36, 0xE0000060L);
    w16(r, pe + 6, nsec + 1);
    w32(r, opt + 56, align(newRva + vsize, sa));                       // SizeOfImage
    w32(r, opt + 8, u32(r, opt + 8) + raw);                            // SizeOfInitializedData

    Files.write(out.toPath(), r);
    return String.format("Wrote %s%nship model table: VA 0x%X, %d entries + TMP (was 73 + TMP)", out.getName(), tabVa, capacity);
  }

  static int v2o(byte[] d, int secTab, int nsec, long base, long vaddr) {
    long rva = vaddr - base;
    for (int i = 0; i < nsec; ++i) {
      int o = secTab + i * 40;
      long va = u32(d, o + 12), rs = u32(d, o + 16), rp = u32(d, o + 20);
      if (rva >= va && rva < va + rs)
        return (int) (rp + rva - va);
    }
    return -1;
  }

  static byte[] hex(String s) {
    byte[] b = new byte[s.length() / 2];
    for (int i = 0; i < b.length; ++i)
      b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
    return b;
  }

  static final String[] DLLS = {
    "mpr555.dll", "mpr555m.dll", "mpr555p.dll", "mpr555pm.dll",
    "mpr565.dll", "mpr565m.dll", "mpr565p.dll", "mpr565pm.dll" };

  static boolean isPatched(File f) throws IOException {
    byte[] d = Files.readAllBytes(f.toPath());
    if (d.length < 0x400 || d[0] != 'M' || d[1] != 'Z') throw new IOException("not a PE exe file");
    int pe = (int) u32(d, 0x3C);
    int nsec = u16(d, pe + 6), secTab = pe + 24 + u16(d, pe + 20);
    for (int i = 0; i < nsec; ++i)
      if (new String(d, secTab + i * 40, 8, "ISO-8859-1").startsWith(".mdl")) return true;
    return false;
  }

  static File backupName(File f) { return new File(f.getParentFile(), f.getName() + ".bak"); }

  /**
   * Patches the selected trek.exe in place and installs the palette-fix DLLs next to it.
   * Existing files are backed up as NAME.bak (an existing .bak is never overwritten, so the first original is kept).
   * Everything is prepared in temp files first, the game files are only touched when that succeeded.
   */
  public static String install(File exe, int cap) throws IOException {
    File dir = exe.getAbsoluteFile().getParentFile();
    StringBuilder log = new StringBuilder();
    boolean patched = isPatched(exe);
    File tmpExe = new File(dir, exe.getName() + ".patch.tmp");
    java.util.List<File> tmps = new java.util.ArrayList<>();
    try {
      // 1. prepare everything
      if (!patched)
        patch(exe, tmpExe, cap);
      for (String n : DLLS) {
        File t = new File(dir, n + ".new.tmp");
        tmps.add(t);
        try (java.io.InputStream in = Patch.class.getResourceAsStream("/dll/" + n)) {
          if (in == null) throw new IOException("patcher is missing the embedded " + n);
          Files.copy(in, t.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
      }
      // 2. backups
      java.util.List<File> targets = new java.util.ArrayList<>();
      if (!patched) targets.add(exe);
      for (String n : DLLS) targets.add(new File(dir, n));
      for (File t : targets) {
        if (!t.exists()) continue;
        File b = backupName(t);
        if (b.exists()) log.append("backup kept (exists): ").append(b.getName()).append('\n');
        else {
          Files.copy(t.toPath(), b.toPath());
          log.append("backup: ").append(b.getName()).append('\n');
        }
      }
      // 3. replace
      java.nio.file.CopyOption[] mv = { java.nio.file.StandardCopyOption.REPLACE_EXISTING };
      if (!patched) {
        Files.move(tmpExe.toPath(), exe.toPath(), mv);
        log.append("patched: ").append(exe.getName()).append(" (").append(cap).append(" ship models)\n");
      } else {
        log.append(exe.getName()).append(" already has the ship model patch, left unchanged\n");
      }
      for (String n : DLLS) {
        Files.move(new File(dir, n + ".new.tmp").toPath(), new File(dir, n).toPath(), mv);
        log.append("installed: ").append(n).append('\n');
      }
    } catch (IOException | RuntimeException e) {
      throw new IOException(e.getMessage() + "\nNo game file was changed unless listed in the backups.", e);
    } finally {
      tmpExe.delete();
      for (File t : tmps) t.delete();
    }
    return log.toString();
  }

  public static void main(String[] args) throws Exception {
    boolean gui = args.length == 0 && !java.awt.GraphicsEnvironment.isHeadless();
    if (args.length >= 2) {   // command line: in out [capacity] -> old behaviour, writes a new file
      File in = new File(args[0]), out = new File(args[1]);
      if (out.getCanonicalFile().equals(in.getCanonicalFile())) { System.err.println("output must differ from input"); System.exit(1); }
      try { System.out.println(patch(in, out, args.length >= 3 ? Integer.parseInt(args[2]) : 512)); }
      catch (IOException e) { System.err.println("FAILED: " + e.getMessage()); System.exit(1); }
      return;
    }
    File in;
    if (gui) {
      javax.swing.JFileChooser fc = new javax.swing.JFileChooser();
      fc.setDialogTitle("Select the trek.exe to patch");
      if (fc.showOpenDialog(null) != javax.swing.JFileChooser.APPROVE_OPTION) return;
      in = fc.getSelectedFile();
    } else if (args.length == 1) {
      in = new File(args[0]);
    } else {
      System.out.println("usage: java -jar Patch.jar [trek.exe]   (patches in place, backups as .bak)\n"
        + "       java -jar Patch.jar trek.exe output.exe [capacity]   (exe only, new file)");
      return;
    }
    String title = "BotF patcher";
    if (gui) {
      String msg = "These files in\n" + in.getAbsoluteFile().getParent() + "\nwill be REPLACED:\n\n  " + in.getName()
        + "\n  mpr555*.dll and mpr565*.dll (8 files, palette limit fix)\n\n"
        + "Backups are saved next to them as NAME.bak (an existing .bak is kept).\nProceed?";
      Object[] opts = { "Proceed", "Cancel" };
      int r = javax.swing.JOptionPane.showOptionDialog(null, msg, title, javax.swing.JOptionPane.DEFAULT_OPTION,
        javax.swing.JOptionPane.WARNING_MESSAGE, null, opts, opts[1]);
      if (r != 0) return;
    }
    try {
      String msg = install(in, 512);
      if (gui) javax.swing.JOptionPane.showMessageDialog(null, msg, title, javax.swing.JOptionPane.INFORMATION_MESSAGE);
      else System.out.println(msg);
    } catch (IOException e) {
      if (gui) javax.swing.JOptionPane.showMessageDialog(null, "FAILED: " + e.getMessage(), title, javax.swing.JOptionPane.ERROR_MESSAGE);
      else { System.err.println("FAILED: " + e.getMessage()); System.exit(1); }
    }
  }
}
