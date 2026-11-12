package com.itsash.netshield

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Target of the widget's On/Off button. Not exported: only the widget's explicit PendingIntent reaches it. */
class WidgetToggleReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != NetShieldWidget.ACTION_TOGGLE) return
        NetShieldWidget.toggle(context)
        NetShieldWidget.updateAll(context)
    }
}
