package com.itsash.netshield

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

/** Turns protection back on after a reboot or an app update, if it was on. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_MY_PACKAGE_REPLACED -> {
                if (ShieldPrefs(context).enabled && VpnService.prepare(context) == null) {
                    runCatching { ShieldVpnService.start(context) }
                }
            }
        }
    }
}

/** Quick Settings tile: protection on and off from the notification shade. */
class ShieldTileService : TileService() {
    override fun onStartListening() {
        super.onStartListening()
        update()
    }

    override fun onClick() {
        super.onClick()
        if (ShieldVpnService.running) {
            ShieldVpnService.stop(this)
        } else if (VpnService.prepare(this) != null) {
            openApp() // The VPN permission prompt needs an activity.
            return
        } else {
            try {
                ShieldVpnService.start(this)
            } catch (_: Throwable) {
                // Some Android versions refuse a foreground-service start here.
                openApp()
                return
            }
        }
        update()
        Handler(Looper.getMainLooper()).postDelayed({ update() }, 1500)
    }

    @Suppress("DEPRECATION")
    private fun openApp() {
        val intent = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startActivityAndCollapse(PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE))
        } else {
            startActivityAndCollapse(intent)
        }
    }

    private fun update() {
        val tile = qsTile ?: return
        val on = ShieldVpnService.running
        tile.state = if (on) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) tile.subtitle = if (on) "On" else "Off"
        tile.updateTile()
    }
}
