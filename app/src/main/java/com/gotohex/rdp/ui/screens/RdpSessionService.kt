package com.gotohex.rdp.ui.screens

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.gotohex.rdp.R
import com.gotohex.rdp.ui.MainActivity

/**
 * Lightweight foreground service whose only job is to keep the app process
 * alive (and show a persistent notification) while an RDP session is
 * connected, so the connection is not torn down by the OS when the user
 * switches apps or locks the screen (issue #9 — "RDP should run in the
 * background so the connection is not lost").
 *
 * The actual [com.gotohex.rdp.rdp.protocol.RdpClient] continues to run inside
 * [RdpSessionViewModel] (via `viewModelScope`, on `Dispatchers.IO`), which is
 * unaffected by the activity's UI lifecycle as long as the process stays
 * alive — this service's purpose is exactly to keep that process alive.
 */
class RdpSessionService : Service() {

    companion object {
        private const val CHANNEL_ID = "rdp_session_channel"
        private const val NOTIFICATION_ID = 42
        private const val EXTRA_PROFILE_NAME = "profile_name"

        fun start(context: Context, profileName: String) {
            val intent = Intent(context, RdpSessionService::class.java)
                .putExtra(EXTRA_PROFILE_NAME, profileName)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, RdpSessionService::class.java))
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val profileName = intent?.getStringExtra(EXTRA_PROFILE_NAME) ?: "RDP"
        val notification = buildNotification(profileName)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            // Must match the android:foregroundServiceType="connectedDevice"
            // declared for this service in the manifest. On API 34+, omitting
            // this throws MissingForegroundServiceTypeException /
            // ForegroundServiceTypeNotAllowedException and crashes the app
            // the moment a session tries to go to the background.
            startForeground(
                NOTIFICATION_ID,
                notification,
                android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
        return START_STICKY
    }

    private fun buildNotification(profileName: String): Notification {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(NotificationManager::class.java)
            if (manager.getNotificationChannel(CHANNEL_ID) == null) {
                manager.createNotificationChannel(
                    NotificationChannel(
                        CHANNEL_ID,
                        getString(R.string.background_session_channel),
                        NotificationManager.IMPORTANCE_LOW
                    )
                )
            }
        }

        val contentIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_REORDER_TO_FRONT),
            PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.background_session_title))
            .setContentText(getString(R.string.background_session_text, profileName))
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setOngoing(true)
            .setContentIntent(contentIntent)
            .build()
    }
}
