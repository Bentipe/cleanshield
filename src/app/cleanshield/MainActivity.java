package app.cleanshield;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

public class MainActivity extends Activity {
    private static final int REQ_VPN = 1;
    private TextView status, recent;
    private Button startBtn, alwaysOnBtn;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable tick = new Runnable() {
        @Override public void run() { refresh(); handler.postDelayed(this, 1000); }
    };

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(64, 360, 64, 64);

        status = new TextView(this);
        status.setTextSize(17);
        root.addView(status);

        startBtn = new Button(this);
        startBtn.setText("Turn on protection");
        startBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                Intent consent = VpnService.prepare(MainActivity.this);
                if (consent != null) startActivityForResult(consent, REQ_VPN);
                else onActivityResult(REQ_VPN, RESULT_OK, null);
            }
        });
        root.addView(startBtn);

        alwaysOnBtn = new Button(this);
        alwaysOnBtn.setText("Make it always-on (VPN settings)");
        alwaysOnBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { startActivity(new Intent(Settings.ACTION_VPN_SETTINGS)); }
        });
        root.addView(alwaysOnBtn);

        recent = new TextView(this);
        recent.setTextSize(13);
        recent.setPadding(0, 40, 0, 0);
        root.addView(recent);

        ScrollView sv = new ScrollView(this);
        sv.addView(root);
        setContentView(sv);
    }

    @Override
    protected void onActivityResult(int req, int result, Intent data) {
        if (req == REQ_VPN && result == RESULT_OK) startService(new Intent(this, ShieldVpnService.class));
    }

    @Override protected void onResume() { super.onResume(); handler.post(tick); }
    @Override protected void onPause() { super.onPause(); handler.removeCallbacks(tick); }

    private void refresh() {
        boolean on = ShieldVpnService.running;
        startBtn.setVisibility(on ? View.GONE : View.VISIBLE);
        long t = ShieldVpnService.total.get(), bl = ShieldVpnService.blocked.get();
        status.setText((on ? "✅ Protection on" : "⛔ Protection off") + "\n\n"
            + "Blocking ads, trackers, porn sites and DNS bypass servers ("
            + String.format("%,d", ShieldVpnService.listSize) + " domains), with SafeSearch forced "
            + "on Google, Bing and DuckDuckGo.\n\n"
            + "Since start: " + String.format("%,d", t) + " lookups, " + String.format("%,d", bl) + " blocked"
            + (t > 0 ? String.format(" (%.0f%%)", 100.0 * bl / t) : "") + "\n\n"
            + "Important: in VPN settings keep \"Block connections without VPN\" (Bloquear conexiones "
            + "sin VPN) OFF. Clean Shield only filters DNS, so with that switch on nothing can connect.\n\n"
            + "Note: it uses Android's VPN slot. Turning on Tailscale, WireGuard, Proton VPN or "
            + "FortiClient switches Clean Shield off until you turn it back on here.");
        StringBuilder sb = new StringBuilder("Recently blocked:\n");
        synchronized (ShieldVpnService.recentBlocked) {
            for (String d : ShieldVpnService.recentBlocked) sb.append("• ").append(d).append('\n');
        }
        recent.setText(sb);
    }
}
