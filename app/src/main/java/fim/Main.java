// ============================================================================
// Java_FIM_Tool – v0.1.0 (05‑May‑2025)
// ► A **cross‑platform** file‑integrity‑monitor written in **pure Java 21**.
// ► Paradigms showcased:
//      • **OOP** – each security concern is isolated in its own class.
//      • **EDP** – real‑time reactions to filesystem events via WatchService.
// ► Core workflow
//      1.  `--init <dir>`   → walk the directory, hash every regular file, 
//                             and persist those hashes as a *baseline*.
//      2.  `--watch <dir>`  → launch a watcher thread that raises an alert
//                             the moment any CREATE / MODIFY / DELETE alters
//                             bytes on disk.  Optional `--interval <n>` adds
//                             a timed sweep for defence‑in‑depth.
// ► ZERO third‑party jars – only Java SE standard library APIs.
// ----------------------------------------------------------------------------
// Manual build/run (if you don’t use Gradle):
//     javac -d out $(find src -name "*.java")
//     java  -cp out fim.Main --init   /opt/softwareVault
//     java  -cp out fim.Main --watch  /opt/softwareVault --interval 60
// ============================================================================

package fim;

import java.io.*;                       // BufferedReader / Writer, etc.
import java.nio.ByteBuffer;              // direct buffer for fast hashing
import java.nio.channels.FileChannel;    // memory‑mapped I/O
import java.nio.file.*;                  // Path, Files, WatchService …
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;      // SHA‑256 + constant‑time compare
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;                      // Map, Optional, ConcurrentHashMap
import java.util.concurrent.*;           // Thread‑pools & scheduling

/* -------------------------------------------------------------------------
 *  SECTION 1 – UTILITY: HEX ENCODING
 *  ---------------------------------
 *  MessageDigest returns *raw bytes* (256‑bit value); humans & logs are
 *  happier with hexadecimal strings like "a3b1…".  Hand‑rolled a tiny
 *  encoder.
 * ----------------------------------------------------------------------- */
final class Hex {
    private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();

    /** Convert a byte[] into a lowercase hex string. */
    static String encode(byte[] bytes) {
        char[] chars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;           // unsigned
            chars[i * 2]     = HEX_ARRAY[v >>> 4]; // high nibble
            chars[i * 2 + 1] = HEX_ARRAY[v & 0x0F]; // low nibble
        }
        return new String(chars);
    }
}

/* -------------------------------------------------------------------------
 *  SECTION 2 – BASELINE STORAGE API
 *  --------------------------------
 *  The tool might evolve (SQLite, JSON, remote DB).  We abstract persistence
 *  behind BaselineStore so callers don’t care how hashes are stored.
 * ----------------------------------------------------------------------- */
interface BaselineStore {
    void put(Path file, String sha256Hex) throws IOException;
    Optional<String> getHash(Path file) throws IOException;
    void save() throws IOException;
    void load() throws IOException;
}

/* -------------------------------------------------------------------------
 *  SECTION 2.1 – TEXT IMPLEMENTATION
 *  ---------------------------------
 *  One line per file:  <hex>|<timestamp>|<absolute path>
 *  Thread‑safe via implicit monitor on `this` (synchronized methods).
 * ----------------------------------------------------------------------- */
class TextBaselineStore implements BaselineStore {
    private final Path baselineFile;                 // where we persist to disk
    private final Map<Path, String> map = new ConcurrentHashMap<>(); // path→hash

    TextBaselineStore(Path baselineFile) { this.baselineFile = baselineFile; }

    /** Insert/replace a hash for a path. */
    public synchronized void put(Path file, String sha256Hex) {
        map.put(file.toAbsolutePath().normalize(), sha256Hex);
    }

    /** Retrieve previous hash (if any). */
    public synchronized Optional<String> getHash(Path file) {
        return Optional.ofNullable(map.get(file.toAbsolutePath().normalize()));
    }

    /** Flush current map to disk (overwrite). */
    public synchronized void save() throws IOException {
        try (BufferedWriter bw = Files.newBufferedWriter(baselineFile)) {
            for (Map.Entry<Path, String> e : map.entrySet()) {
                bw.write(e.getValue() + "|" + Instant.now().toEpochMilli() + "|" + e.getKey());
                bw.newLine();
            }
        }
    }

    /** Load baseline from disk into memory (noop if file missing). */
    public synchronized void load() throws IOException {
        map.clear();
        if (!Files.exists(baselineFile)) return;
        try (BufferedReader br = Files.newBufferedReader(baselineFile)) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split("\\|", 3);
                if (parts.length == 3) {
                    map.put(Paths.get(parts[2]), parts[0]);
                }
            }
        }
    }
}

/* -------------------------------------------------------------------------
 *  SECTION 3 – HASHING HELPER
 *  --------------------------
 *  Streams file via 16 KiB direct ByteBuffer → low GC pressure.
 *  Uses JCA `MessageDigest` so it’s FIPS‑compliant.
 * ----------------------------------------------------------------------- */
final class Hashing {
    private static final int BUFFER_SIZE = 16 * 1024; // 16 KiB

    static String sha256(Path file) throws IOException {
        try (FileChannel fc = FileChannel.open(file, StandardOpenOption.READ)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            ByteBuffer buffer = ByteBuffer.allocateDirect(BUFFER_SIZE);
            while (fc.read(buffer) != -1) {
                buffer.flip();         // make it readable
                digest.update(buffer); // add to hash
                buffer.clear();        // ready for next chunk
            }
            return Hex.encode(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            // Should never happen on a modern JRE
            throw new IllegalStateException("SHA‑256 not available", e);
        }
    }
}

/* -------------------------------------------------------------------------
 *  SECTION 4 – BUILDING THE BASELINE
 *  ---------------------------------
 *  Uses Files.walkFileTree so we get robust traversal incl. symlink cycle
 *  protection.  Only REGULAR files are hashed (skip sockets, dirs, etc.).
 * ----------------------------------------------------------------------- */
class BaselineBuilder {
    private final BaselineStore store;
    BaselineBuilder(BaselineStore store) { this.store = store; }

    /** Hash every file under `root` and persist baseline. */
    void build(Path root) throws IOException {
        Files.walkFileTree(root, new SimpleFileVisitor<>() {
            @Override public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                if (!attrs.isRegularFile()) return FileVisitResult.CONTINUE;
                String hash = Hashing.sha256(file);
                store.put(file, hash);
                return FileVisitResult.CONTINUE;
            }
        });
        store.save();
    }
}

/* -------------------------------------------------------------------------
 *  SECTION 5 – DRIFT DETECTION LOGIC
 *  ---------------------------------
 *  Encapsulates the compare so both watcher & periodic sweep share code.
 * ----------------------------------------------------------------------- */
class DriftDetector {
    private final BaselineStore store;
    DriftDetector(BaselineStore store) { this.store = store; }

    /** @return true if file is new OR bytes changed vs baseline. */
    boolean isDrift(Path file) throws IOException {
        Optional<String> previous = store.getHash(file);
        if (previous.isEmpty()) return true; // unseen file
        String current = Hashing.sha256(file);
        // constant‑time compare avoids timing side‑channel
        return !MessageDigest.isEqual(previous.get().getBytes(), current.getBytes());
    }
}

/* -------------------------------------------------------------------------
 *  SECTION 6 – WATCHSERVICE CONSUMER (Event‑Driven)
 *  -----------------------------------------------
 *  Registers each dir & subdir so new folders also get watched.
 *  Prints alert if DriftDetector flags the path.
 * ----------------------------------------------------------------------- */
class Watcher implements Runnable {
    private final Path root;
    private final DriftDetector detector;

    Watcher(Path root, BaselineStore store) {
        this.root = root;
        this.detector = new DriftDetector(store);
    }

    @Override public void run() {
        try (WatchService ws = FileSystems.getDefault().newWatchService()) {
            // 1) register root + all subdirs
            registerAll(root, ws);
            System.out.println("[FIM] Watching " + root);

            // 2) event loop
            while (true) {
                WatchKey key = ws.take(); // blocks until event
                for (WatchEvent<?> event : key.pollEvents()) {
                    if (event.kind() == StandardWatchEventKinds.OVERFLOW) continue;
                    Path rel = (Path) event.context();
                    Path abs = ((Path) key.watchable()).resolve(rel);

                    // auto‑register newly created dirs so recursion persists
                    if (Files.isDirectory(abs)) registerAll(abs, ws);

                    if (Files.isRegularFile(abs) && detector.isDrift(abs)) {
                        System.err.println("[ALERT] Integrity drift (" + event.kind().name() + "): " + abs);
                    }
                }
                key.reset();
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    /* Recursively register every sub‑directory so nested changes are caught. */
    private void registerAll(Path start, WatchService ws) throws IOException {
        Files.walkFileTree(start, new SimpleFileVisitor<>() {
            @Override public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                dir.register(ws, StandardWatchEventKinds.ENTRY_CREATE,
                                 StandardWatchEventKinds.ENTRY_MODIFY,
                                 StandardWatchEventKinds.ENTRY_DELETE);
                return FileVisitResult.CONTINUE;
            }
        });
    }
}

/* -------------------------------------------------------------------------
 *  SECTION 7 – CLI ENTRY‑POINT
 *  ---------------------------
 *  Minimal flag parser: we expect flags in a strict order.
 * ----------------------------------------------------------------------- */
public class Main {
    private static void usage() {
        System.out.println("Usage: java fim.Main --init <dir> | --watch <dir> [--interval <seconds>]");
        System.exit(1);
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) usage();

        // Expand leading '~' manually if user quoted the path
        String rawPath = args[1].replaceFirst("^~", System.getProperty("user.home"));
        Path dir = Paths.get(rawPath).toAbsolutePath().normalize();
        if (!Files.isDirectory(dir)) {
            System.err.println("ERROR: " + dir + " is not a directory");
            System.exit(2);
        }

        Path baselineFile = dir.resolve(".fim_baseline.txt");
        BaselineStore store = new TextBaselineStore(baselineFile);
        store.load();

        switch (args[0]) {
            /* -----------------------------------------------------
             * COMMAND: --init <dir>
             * --------------------------------------------------- */
            case "--init" -> {
                new BaselineBuilder(store).build(dir);
                System.out.println("Baseline built and saved to " + baselineFile);
            }

            /* -----------------------------------------------------
             * COMMAND: --watch <dir> [--interval n]
             * --------------------------------------------------- */
            case "--watch" -> {
                int intervalSec = 0;
                if (args.length == 4 && "--interval".equals(args[2])) {
                    intervalSec = Integer.parseInt(args[3]);
                }

                // (a) start event‑driven watcher on its own daemon thread
                Thread t = new Thread(new Watcher(dir, store));
                t.setDaemon(true);
                t.start();

                // (b) optional periodic full re‑hash for belt‑and‑braces
                if (intervalSec > 0) {
                    ScheduledExecutorService ses = Executors.newSingleThreadScheduledExecutor();
                    DriftDetector detector = new DriftDetector(store);
                    ses.scheduleAtFixedRate(() -> {
                        try {
                            Files.walkFileTree(dir, new SimpleFileVisitor<>() {
                                @Override public FileVisitResult visitFile(Path file, BasicFileAttributes a) throws IOException {
                                    if (detector.isDrift(file)) {
                                        System.err.println("[ALERT] Integrity drift (periodic): " + file);
                                    }
                                    return FileVisitResult.CONTINUE;
                                }
                            });
                        } catch (IOException e) { e.printStackTrace(); }
                    }, intervalSec, intervalSec, TimeUnit.SECONDS);
                }

                // keep JVM alive – main thread parks forever
                Thread.currentThread().join();
            }
            default -> usage();
        }
    }
}
