package app.cleanshield;

import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.system.OsConstants;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A DNS-only VPN: the phone's DNS server is set to a fake address inside the tunnel, so every
 * lookup arrives here. Blocked names get NXDOMAIN; the rest go over HTTPS to Cloudflare for
 * Families (which also blocks malware and adult sites). All other traffic bypasses the tunnel.
 */
public class ShieldVpnService extends VpnService {
    static final String TAG = "CleanShield";
    private static final String DNS_IP = "10.111.222.53";
    /** Public resolvers apps sometimes hard-code; their port-53 traffic is filtered too, anything else dropped. */
    private static final String[] HIJACK = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
        "149.112.112.112", "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15"};
    private static final String[] UPSTREAM = {"https://1.1.1.3/dns-query", "https://1.0.0.3/dns-query"};

    static final AtomicLong total = new AtomicLong(), blocked = new AtomicLong();
    static final ArrayDeque<String> recentBlocked = new ArrayDeque<>();
    static volatile boolean running;
    static volatile int listSize;

    private final Filter filter = new Filter();
    private ParcelFileDescriptor tun;
    private Thread reader;
    private ExecutorService pool;
    private FileOutputStream out;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (reader == null) start();
        return START_STICKY;
    }

    private synchronized void start() {
        try {
            filter.load(this);
            listSize = filter.size();
        } catch (IOException e) {
            Log.e(TAG, "could not load blocklist", e);
        }
        Builder b = new Builder()
            .setSession("Clean Shield")
            .addAddress("10.111.222.1", 32)
            .addDnsServer(DNS_IP)
            .addRoute(DNS_IP, 32)
            .allowFamily(OsConstants.AF_INET6)   // don't block IPv6 traffic, just leave it alone
            .setBlocking(true)
            .setMtu(4096)
            .setConfigureIntent(PendingIntent.getActivity(this, 0,
                new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE));
        for (String ip : HIJACK) b.addRoute(ip, 32);
        b.setMetered(false);
        try {
            b.addDisallowedApplication(getPackageName()); // our own HTTPS lookups go straight out
        } catch (Exception ignored) {}
        tun = b.establish();
        if (tun == null) { Log.w(TAG, "VPN permission missing"); stopSelf(); return; }
        out = new FileOutputStream(tun.getFileDescriptor());
        pool = Executors.newFixedThreadPool(12);
        running = true;
        reader = new Thread(new Runnable() { @Override public void run() { readLoop(); } }, "dns-reader");
        reader.start();
        Log.i(TAG, "started with " + listSize + " blocked domains");
    }

    private void readLoop() {
        FileInputStream in = new FileInputStream(tun.getFileDescriptor());
        byte[] buf = new byte[32767];
        while (running) {
            int n;
            try { n = in.read(buf); } catch (IOException e) { break; }
            if (n <= 28 || (buf[0] >> 4) != 4 || buf[9] != 17) continue;  // IPv4 UDP only
            int ihl = (buf[0] & 0x0f) * 4;
            int dport = (buf[ihl + 2] & 0xff) << 8 | (buf[ihl + 3] & 0xff);
            if (dport != 53) continue;
            final byte[] packet = new byte[n];
            System.arraycopy(buf, 0, packet, 0, n);
            pool.execute(new Runnable() { @Override public void run() { handle(packet); } });
        }
    }

    private void handle(byte[] packet) {
        int ihl = (packet[0] & 0x0f) * 4;
        int off = ihl + 8;
        byte[] query = new byte[packet.length - off];
        System.arraycopy(packet, off, query, 0, query.length);
        Dns.Question q = Dns.parseQuestion(query, query.length);
        if (q == null) return;
        total.incrementAndGet();
        byte[] answer;
        try {
            if (filter.isBlocked(q.name)) {
                blocked.incrementAndGet();
                remember(q.name);
                answer = Dns.reply(query, q, 3, null);                     // NXDOMAIN
            } else {
                String safe = Filter.safeSearchTarget(q.name);
                if (safe != null && q.type == Dns.TYPE_A) {
                    List<byte[]> ips = Dns.answersA(resolve(Dns.query(safe, Dns.TYPE_A)));
                    answer = Dns.reply(query, q, 0, ips);
                } else if (safe != null && q.type == Dns.TYPE_AAAA) {
                    answer = Dns.reply(query, q, 0, new ArrayList<byte[]>()); // force IPv4 SafeSearch
                } else {
                    answer = resolve(query);
                }
            }
        } catch (IOException e) {
            Log.w(TAG, "upstream failed for " + q.name + ": " + e);
            answer = Dns.reply(query, q, 2, null);                         // SERVFAIL
        }
        if (BuildConfigDebug.ON) {
            List<byte[]> a = Dns.answersA(answer);
            Log.d(TAG, q.name + " type=" + q.type + " rcode=" + (answer[3] & 0x0f) + " len=" + answer.length
                + (a.isEmpty() ? "" : " A=" + (a.get(0)[0] & 0xff) + "." + (a.get(0)[1] & 0xff) + "."
                + (a.get(0)[2] & 0xff) + "." + (a.get(0)[3] & 0xff)));
        }
        byte[] reply = Dns.udpReply(packet, answer);
        synchronized (this) {
            try { if (out != null) out.write(reply); } catch (IOException ignored) {}
        }
    }

    private byte[] resolve(byte[] query) throws IOException {
        IOException last = null;
        for (String u : UPSTREAM) {
            HttpURLConnection c = null;
            try {
                c = (HttpURLConnection) new URL(u).openConnection();
                c.setConnectTimeout(4000);
                c.setReadTimeout(4000);
                c.setDoOutput(true);
                c.setRequestMethod("POST");
                c.setRequestProperty("Content-Type", "application/dns-message");
                c.setRequestProperty("Accept", "application/dns-message");
                OutputStream os = c.getOutputStream();
                os.write(query);
                os.close();
                if (c.getResponseCode() != 200) throw new IOException("HTTP " + c.getResponseCode());
                InputStream is = c.getInputStream();
                ByteArrayOutputStream bo = new ByteArrayOutputStream();
                byte[] b = new byte[4096];
                int n;
                while ((n = is.read(b)) > 0) bo.write(b, 0, n);
                is.close();
                return bo.toByteArray();
            } catch (IOException e) {
                last = e;
                if (c != null) c.disconnect();
            }
        }
        throw last;
    }

    private static void remember(String name) {
        synchronized (recentBlocked) {
            recentBlocked.remove(name);
            recentBlocked.addFirst(name);
            while (recentBlocked.size() > 40) recentBlocked.removeLast();
        }
    }

    private synchronized void shutdown() {
        running = false;
        if (pool != null) pool.shutdownNow();
        try { if (tun != null) tun.close(); } catch (IOException ignored) {}
        tun = null;
        out = null;
        reader = null;
    }

    @Override
    public void onRevoke() {
        Log.w(TAG, "VPN revoked (another VPN took over or it was switched off)");
        shutdown();
        stopSelf();
    }

    @Override
    public void onDestroy() {
        shutdown();
        super.onDestroy();
    }
}
