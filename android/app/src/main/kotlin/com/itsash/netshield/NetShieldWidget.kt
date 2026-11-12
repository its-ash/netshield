package com.itsash.netshield

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.widget.RemoteViews

/**
 * Home-screen widget: protection on/off, blocked and total queries today, and a toggle.
 * Reads the same in-process state the notification uses (`ShieldVpnService.running`,
 * `TodayStats`); the service calls [updateAll] on state changes and from its tick.
 */
class NetShieldWidget : AppWidgetProvider() {

    override fun onUpdate(context: Context, manager: AppWidgetManager, appWidgetIds: IntArray) {
        val views = build(context)
        for (id in appWidgetIds) manager.updateAppWidget(id, views)
    }

    // Exported only for the system's APPWIDGET_UPDATE; the toggle lives in the
    // non-exported WidgetToggleReceiver, so this receiver ignores any other action.
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == ACTION_TOGGLE) return
        super.onReceive(context, intent)
    }

    companion object {
        const val ACTION_TOGGLE = "com.itsash.netshield.WIDGET_TOGGLE"
        private const val REQUEST_TOGGLE = 31
        private const val REQUEST_OPEN = 32

        @Volatile
        private var lastPush = 0L

        /** Pushes the current state to every placed widget. Cheap when none is placed. */
        fun updateAll(context: Context) {
            val manager = AppWidgetManager.getInstance(context)
            val ids = manager.getAppWidgetIds(ComponentName(context, NetShieldWidget::class.java))
            if (ids.isEmpty()) return
            lastPush = System.currentTimeMillis()
            val views = build(context)
            for (id in ids) manager.updateAppWidget(id, views)
        }

        /** Like [updateAll], at most once per [minGapMs] (for the service's periodic tick). */
        fun updateThrottled(context: Context, minGapMs: Long = 30_000) {
            if (System.currentTimeMillis() - lastPush >= minGapMs) updateAll(context)
        }

        /** Off stops the service; On starts it if VPN consent is already given, else opens the app. */
        internal fun toggle(context: Context) {
            if (ShieldVpnService.running) {
                ShieldVpnService.stop(context)
            } else if (VpnService.prepare(context) != null) {
                openApp(context)
            } else {
                try {
                    ShieldVpnService.start(context)
                } catch (_: Throwable) {
                    openApp(context)
                }
            }
        }

        internal fun openApp(context: Context) {
            runCatching { openAppIntent(context).send() }
        }

        private fun openAppIntent(context: Context): PendingIntent = PendingIntent.getActivity(
            context,
            REQUEST_OPEN,
            Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        private fun build(context: Context): RemoteViews {
            val on = ShieldVpnService.running
            val (total, blocked) = TodayStats.read(ShieldPrefs(context))
            val toggle = PendingIntent.getBroadcast(
                context,
                REQUEST_TOGGLE,
                Intent().setClass(context, WidgetToggleReceiver::class.java).setAction(ACTION_TOGGLE),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
            return RemoteViews(context.packageName, R.layout.widget_netshield).apply {
                setTextViewText(R.id.widget_state, context.getString(if (on) R.string.widget_state_on else R.string.widget_state_off))
                setTextColor(R.id.widget_state, context.getColor(if (on) R.color.widget_accent else R.color.widget_off))
                setTextViewText(R.id.widget_blocked, context.getString(R.string.widget_blocked, blocked.toString()))
                setTextViewText(R.id.widget_total, context.getString(R.string.widget_of_total, total.toString()))
                setTextViewText(R.id.widget_toggle, context.getString(if (on) R.string.widget_turn_off else R.string.widget_turn_on))
                setOnClickPendingIntent(R.id.widget_toggle, toggle)
                setOnClickPendingIntent(R.id.widget_info, openAppIntent(context))
            }
        }
    }
}
