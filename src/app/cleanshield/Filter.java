package app.cleanshield;

import android.content.Context;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/** Decides what happens to each DNS name: block, rewrite to a SafeSearch host, or pass through. */
final class Filter {
    /** Never blocked, even if a list contains them (suffix match). Add entries here if something breaks. */
    private static final Set<String> ALLOW = new HashSet<>(Arrays.asList(
        "connectivitycheck.gstatic.com", "clients3.google.com", "android.clients.google.com",
        "play.googleapis.com", "time.android.com"));

    /** Always blocked: tells Firefox to switch off its own DNS-over-HTTPS so it can't bypass the filter. */
    private static final Set<String> ALWAYS_BLOCK = new HashSet<>(Arrays.asList(
        "use-application-dns.net"));

    private static final Pattern GOOGLE = Pattern.compile("^(www\\.)?google\\.[a-z]{2,3}(\\.[a-z]{2})?$");

    private long[] hashes = new long[0];

    void load(Context c) throws IOException {
        InputStream in = c.getAssets().open("blocklist.bin");
        ByteArrayOutputStream buf = new ByteArrayOutputStream(8 << 20);
        byte[] chunk = new byte[1 << 16];
        int n;
        while ((n = in.read(chunk)) > 0) buf.write(chunk, 0, n);
        in.close();
        byte[] all = buf.toByteArray();
        long[] h = new long[all.length / 8];
        ByteBuffer.wrap(all).asLongBuffer().get(h); // big-endian, already sorted
        hashes = h;
    }

    int size() { return hashes.length; }

    boolean isBlocked(String name) {
        if (matchesSuffix(name, ALWAYS_BLOCK)) return true;
        if (matchesSuffix(name, ALLOW)) return false;
        String d = name;
        while (true) {
            if (Arrays.binarySearch(hashes, fnv1a64(d)) >= 0) return true;
            int dot = d.indexOf('.');
            if (dot < 0 || d.indexOf('.', dot + 1) < 0) return false; // stop before the bare TLD
            d = d.substring(dot + 1);
        }
    }

    /** Returns the SafeSearch host to answer with instead, or null. */
    static String safeSearchTarget(String name) {
        if (GOOGLE.matcher(name).matches()) return "forcesafesearch.google.com";
        switch (name) {
            case "bing.com": case "www.bing.com":
                return "strict.bing.com";
            case "duckduckgo.com": case "www.duckduckgo.com": case "start.duckduckgo.com":
            case "html.duckduckgo.com": case "duck.com":
                return "safe.duckduckgo.com";
            case "www.youtube.com": case "m.youtube.com": case "youtube.com":
            case "youtubei.googleapis.com": case "youtube.googleapis.com":
            case "www.youtube-nocookie.com":
                return "restrict.youtube.com";
            default:
                return null;
        }
    }

    static String normalize(String name) {
        String s = name.toLowerCase(Locale.ROOT);
        while (s.endsWith(".")) s = s.substring(0, s.length() - 1);
        return s;
    }

    private static boolean matchesSuffix(String name, Set<String> set) {
        String d = name;
        while (true) {
            if (set.contains(d)) return true;
            int dot = d.indexOf('.');
            if (dot < 0) return false;
            d = d.substring(dot + 1);
        }
    }

    static long fnv1a64(String s) {
        long h = 0xcbf29ce484222325L;
        for (byte b : s.getBytes(StandardCharsets.UTF_8)) {
            h ^= (b & 0xff);
            h *= 0x100000001b3L;
        }
        return h;
    }
}
