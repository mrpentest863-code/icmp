package com.example.pingtunnel

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.Toast

class MainActivity : Activity() {
    private lateinit var connectBtn: Button
    private lateinit var disconnectBtn: Button
    private lateinit var server: EditText
    private lateinit var username: EditText
    private lateinit var password: EditText

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        connectBtn = findViewById(R.id.connectBtn)
        disconnectBtn = findViewById(R.id.disconnectBtn)
        server = findViewById(R.id.server)
        username = findViewById(R.id.username)
        password = findViewById(R.id.password)

        connectBtn.setOnClickListener {
            val intent = VpnService.prepare(this)
            if (intent != null) {
                startActivityForResult(intent, 0)
            } else {
                startVpn()
            }
        }

        disconnectBtn.setOnClickListener {
            stopVpn()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode == RESULT_OK) {
            startVpn()
        } else {
            Toast.makeText(this, "Permission VPN refusée", Toast.LENGTH_SHORT).show()
        }
    }

    private fun startVpn() {
        val intent = Intent(this, MyVpnService::class.java)
        intent.putExtra("server", server.text.toString())
        intent.putExtra("user", username.text.toString())
        intent.putExtra("pass", password.text.toString())
        startService(intent)
        connectBtn.isEnabled = false
        disconnectBtn.isEnabled = true
    }

    private fun stopVpn() {
        stopService(Intent(this, MyVpnService::class.java))
        connectBtn.isEnabled = true
        disconnectBtn.isEnabled = false
    }
}
