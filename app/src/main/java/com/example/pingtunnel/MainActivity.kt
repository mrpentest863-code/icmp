package com.example.pingtunnel

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.Toast

class MainActivity : Activity() {

    companion object {
        private const val VPN_REQUEST_CODE = 1000
    }

    private lateinit var connectBtn: Button
    private lateinit var server: EditText
    private lateinit var username: EditText
    private lateinit var password: EditText
    private var isConnected = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        connectBtn = findViewById(R.id.connectBtn)
        server = findViewById(R.id.server)
        username = findViewById(R.id.username)
        password = findViewById(R.id.password)

        connectBtn.setOnClickListener {
            if (isConnected) {
                stopVpn()
            } else {
                if (!validateInputs()) return@setOnClickListener

                connectBtn.isEnabled = false
                connectBtn.text = "Connexion..."

                val intent = VpnService.prepare(this)
                if (intent != null) {
                    startActivityForResult(intent, VPN_REQUEST_CODE)
                } else {
                    startVpn()
                }
            }
        }
    }

    private fun validateInputs(): Boolean {
        if (server.text.isBlank() || username.text.isBlank() || password.text.isBlank()) {
            Toast.makeText(this, "Veuillez remplir tous les champs", Toast.LENGTH_SHORT).show()
            return false
        }
        return true
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode != VPN_REQUEST_CODE) return

        if (resultCode == RESULT_OK) {
            startVpn()
        } else {
            connectBtn.isEnabled = true
            connectBtn.text = "Connecter"
            Toast.makeText(this, "Autorisation VPN refusée", Toast.LENGTH_SHORT).show()
        }
    }

    private fun startVpn() {
        val intent = Intent(this, MyVpnService::class.java)
        intent.putExtra("server", server.text.toString())
        intent.putExtra("user", username.text.toString())
        intent.putExtra("pass", password.text.toString())
        startService(intent)

        isConnected = true
        connectBtn.isEnabled = true
        connectBtn.text = "Déconnecter"
    }

    private fun stopVpn() {
        stopService(Intent(this, MyVpnService::class.java))
        isConnected = false
        connectBtn.isEnabled = true
        connectBtn.text = "Connecter"
    }
}
