package com.example.pingtunnel

import android.net.VpnService
import android.content.Intent
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import android.widget.Toast
import java.io.File
import java.io.IOException

class MyVpnService : VpnService() {

    companion object {
        private const val TAG = "MyVpnService"
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var tunnelProcess: Process? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val server = intent?.getStringExtra("server")
        val user = intent?.getStringExtra("user")
        val pass = intent?.getStringExtra("pass")

        if (server.isNullOrEmpty() || user.isNullOrEmpty() || pass.isNullOrEmpty()) {
            Log.e(TAG, "Paramètres manquants (server/user/pass)")
            stopSelf()
            return START_NOT_STICKY
        }

        val binary = try {
            copyBinary()
        } catch (e: IOException) {
            Log.e(TAG, "Échec de la copie du binaire", e)
            stopSelf()
            return START_NOT_STICKY
        }

        val builder = Builder()
        builder.setSession("PingTunnel VPN")
        builder.addAddress("10.0.0.2", 24)
        builder.addRoute("0.0.0.0", 0)
        builder.addDnsServer("8.8.8.8")

        val iface = builder.establish()
        if (iface == null) {
            // Permission VPN non accordée ou établissement impossible
            Log.e(TAG, "builder.establish() a renvoyé null")
            stopSelf()
            return START_NOT_STICKY
        }
        vpnInterface = iface

        // detachFd() transfère la propriété du fd : il ne sera pas fermé par le
        // ParcelFileDescriptor côté Java, et pourra être utilisé par le process fils.
        // C'est indispensable pour qu'il survive à l'exec() du binaire natif.
        val fd = iface.detachFd()

        try {
            tunnelProcess = ProcessBuilder(
                binary.absolutePath,
                server,
                user,
                pass,
                fd.toString()
            ).redirectErrorStream(true).start()
        } catch (e: Exception) {
            Log.e(TAG, "Échec du lancement du process tunnel", e)
            // le fd a été détaché : on doit le fermer nous-mêmes puisque
            // aucun process n'en a pris possession
            ParcelFileDescriptor.adoptFd(fd).close()
            vpnInterface = null
            stopSelf()
            return START_NOT_STICKY
        }

        Toast.makeText(this, "VPN connecté", Toast.LENGTH_SHORT).show()
        return START_STICKY
    }

    private fun copyBinary(): File {
        val abi = Build.SUPPORTED_ABIS.first()
        val assetPath = if (abi.contains("64")) {
            "arm64-v8a/pingtunnel_cpp"
        } else {
            "armeabi-v7a/pingtunnel_cpp"
        }
        val outFile = File(filesDir, "pingtunnel_cpp")
        if (!outFile.exists()) {
            assets.open(assetPath).use { input ->
                outFile.outputStream().use { output ->
                    input.copyTo(output)
                }
            }
            if (!outFile.setExecutable(true)) {
                Log.w(TAG, "Impossible de rendre le binaire exécutable")
            }
        }
        return outFile
    }

    override fun onRevoke() {
        // Appelé si l'utilisateur révoque l'autorisation VPN depuis les paramètres système
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        tunnelProcess?.destroy()
        tunnelProcess = null

        try {
            vpnInterface?.close()
        } catch (e: IOException) {
            Log.e(TAG, "Erreur à la fermeture de l'interface VPN", e)
        }
        vpnInterface = null

        Toast.makeText(this, "VPN déconnecté", Toast.LENGTH_SHORT).show()
        super.onDestroy()
        // pas de stopSelf() ici : on est déjà dans onDestroy(), l'appeler
        // à nouveau est redondant et peut créer une boucle d'appels
    }
}
