package app.cleanshield;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/** Minimal DNS message and IPv4/UDP packet helpers. */
final class Dns {
    private Dns() {}

    static final int TYPE_A = 1, TYPE_AAAA = 28;

    static final class Question {
        String name;
        int type;
        int end; // offset just past the question section
    }

    static Question parseQuestion(byte[] m, int len) {
        if (len < 12 || ((m[4] & 0xff) << 8 | (m[5] & 0xff)) < 1) return null;
        StringBuilder sb = new StringBuilder();
        int p = 12;
        while (p < len) {
            int l = m[p] & 0xff;
            if (l == 0) { p++; break; }
            if ((l & 0xc0) != 0 || p + 1 + l > len) return null;
            if (sb.length() > 0) sb.append('.');
            sb.append(new String(m, p + 1, l, StandardCharsets.ISO_8859_1));
            p += 1 + l;
        }
        if (p + 4 > len) return null;
        Question q = new Question();
        q.name = Filter.normalize(sb.toString());
        q.type = (m[p] & 0xff) << 8 | (m[p + 1] & 0xff);
        q.end = p + 4;
        return q;
    }

    /** A reply with the query's header and question and the given rcode, plus optional IPv4 answers. */
    static byte[] reply(byte[] query, Question q, int rcode, List<byte[]> ipv4) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(query, 0, 2);                                // id
        out.write(0x80 | (query[2] & 0x01));                   // QR, keep RD
        out.write(0x80 | rcode);                               // RA, rcode
        out.write(0); out.write(1);                            // qdcount
        int an = ipv4 == null ? 0 : ipv4.size();
        out.write(an >> 8); out.write(an & 0xff);              // ancount
        out.write(0); out.write(0); out.write(0); out.write(0);
        out.write(query, 12, q.end - 12);                      // question
        if (ipv4 != null) {
            for (byte[] ip : ipv4) {
                out.write(0xc0); out.write(0x0c);              // name -> question
                out.write(0); out.write(1);                    // A
                out.write(0); out.write(1);                    // IN
                out.write(0); out.write(0); out.write(0x01); out.write(0x2c); // ttl 300
                out.write(0); out.write(4);
                out.write(ip, 0, 4);
            }
        }
        return out.toByteArray();
    }

    static byte[] query(String name, int type) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int id = new Random().nextInt(0xffff);
        out.write(id >> 8); out.write(id & 0xff);
        out.write(0x01); out.write(0x00);                      // RD
        out.write(0); out.write(1);
        for (int i = 0; i < 6; i++) out.write(0);
        for (String label : name.split("\\.")) {
            byte[] b = label.getBytes(StandardCharsets.ISO_8859_1);
            out.write(b.length);
            out.write(b, 0, b.length);
        }
        out.write(0);
        out.write(type >> 8); out.write(type & 0xff);
        out.write(0); out.write(1);
        return out.toByteArray();
    }

    /** Extracts IPv4 addresses from the answer section of a response. */
    static List<byte[]> answersA(byte[] m) {
        List<byte[]> ips = new ArrayList<>();
        Question q = parseQuestion(m, m.length);
        if (q == null) return ips;
        int an = (m[6] & 0xff) << 8 | (m[7] & 0xff);
        int p = q.end;
        for (int i = 0; i < an && p < m.length; i++) {
            p = skipName(m, p);
            if (p + 10 > m.length) break;
            int type = (m[p] & 0xff) << 8 | (m[p + 1] & 0xff);
            int rdlen = (m[p + 8] & 0xff) << 8 | (m[p + 9] & 0xff);
            p += 10;
            if (type == TYPE_A && rdlen == 4 && p + 4 <= m.length) {
                byte[] ip = new byte[4];
                System.arraycopy(m, p, ip, 0, 4);
                ips.add(ip);
            }
            p += rdlen;
        }
        return ips;
    }

    private static int skipName(byte[] m, int p) {
        while (p < m.length) {
            int l = m[p] & 0xff;
            if (l == 0) return p + 1;
            if ((l & 0xc0) == 0xc0) return p + 2;
            p += 1 + l;
        }
        return p;
    }

    // --- IPv4 / UDP -----------------------------------------------------------------------------

    /** Wraps a DNS payload in an IPv4/UDP packet going back to whoever sent {@code request}. */
    static byte[] udpReply(byte[] request, byte[] payload) {
        int ihl = (request[0] & 0x0f) * 4;
        int total = 20 + 8 + payload.length;
        byte[] p = new byte[total];
        p[0] = 0x45;
        p[2] = (byte) (total >> 8); p[3] = (byte) total;
        p[6] = 0x40;                                           // don't fragment
        p[8] = 64;                                             // ttl
        p[9] = 17;                                             // UDP
        System.arraycopy(request, 16, p, 12, 4);               // src = original dst
        System.arraycopy(request, 12, p, 16, 4);               // dst = original src
        int sum = 0;
        for (int i = 0; i < 20; i += 2) sum += ((p[i] & 0xff) << 8) | (p[i + 1] & 0xff);
        while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);
        int cks = ~sum & 0xffff;
        p[10] = (byte) (cks >> 8); p[11] = (byte) cks;
        p[20] = request[ihl + 2]; p[21] = request[ihl + 3];    // src port = original dst port (53)
        p[22] = request[ihl]; p[23] = request[ihl + 1];        // dst port = original src port
        int ulen = 8 + payload.length;
        p[24] = (byte) (ulen >> 8); p[25] = (byte) ulen;
        // UDP checksum 0 = not computed (allowed for IPv4)
        System.arraycopy(payload, 0, p, 28, payload.length);
        return p;
    }
}
