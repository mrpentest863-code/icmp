package com.example.pingtunnel

import android.app.Service
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.widget.Toast
import java.io.File

class MyVpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null
    private var tunnelProcess: Process? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val server = intent?.getStringExtra("server") ?: return START_NOT_STICKY
        val user = intent?.getStringExtra("user") ?: return START_NOT_STICKY
        val pass = intent?.getStringExtra("pass") ?: return START_NOT_STICKY

        val binary = copyBinary()

        try {
            tunnelProcess = ProcessBuilder(binary.absolutePath, server, user, pass)
                .redirectErrorStream(true)
                .start()
        } catch (e: Exception) {
            e.printStackTrace()
            stopSelf()
            return START_NOT_STICKY
        }

        val builder = Builder()
        builder.setSession("PingTunnel VPN")
        builder.addAddress("10.0.0.2", 24)
        builder.addRoute("0.0.0.0", 0)
        builder.addDnsServer("8.8.8.8")
        vpnInterface = builder.establish()

        Toast.makeText(this, "VPN connecté", Toast.LENGTH_SHORT).show()
        return START_STICKY
    }

    private fun copyBinary(): File {
        val abi = Build.SUPPORTED_ABIS[0]
        val assetPath = if (abi.contains("64")) "arm64-v8a/pingtunnel_cpp" else "armeabi-v7a/pingtunnel_cpp"
        val outFile = File(filesDir, "pingtunnel_cpp")
        if (!outFile.exists()) {
            assets.open(assetPath).use { input ->
                outFile.outputStream().use { output ->
                    input.copyTo(output)
                }
            }
            outFile.setExecutable(true)
        }
        return outFile
    }

    override fun onDestroy() {
        vpnInterface?.close()
        tunnelProcess?.destroy()
        Toast.makeText(this, "VPN déconnecté", Toast.LENGTH_SHORT).show()
        super.onDestroy()
    }
}
