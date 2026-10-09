package com.ant.proxy

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.OpenableColumns
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.ant.proxy.databinding.ActivityMainBinding
import java.io.File
import java.io.FileOutputStream

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val handler = Handler(Looper.getMainLooper())

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            updateUi()
        }
    }

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpnService()
        } else {
            Toast.makeText(this, "未授予 VPN 权限", Toast.LENGTH_SHORT).show()
            updateUi()
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* optional */ }

    private val importConfigLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri == null) return@registerForActivityResult
        importConfigFromUri(uri)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        applySystemBarInsets(binding.root)

        binding.btnToggle.setOnClickListener {
            if (AntVpnService.isRunning) {
                stopVpnService()
            } else {
                prepareAndStart()
            }
        }

        binding.btnLogs.setOnClickListener {
            startActivity(Intent(this, LogsActivity::class.java))
        }

        binding.btnSettings.setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }

        updateUi()
        refreshConfigStatus()
    }

    override fun onStart() {
        super.onStart()
        val filter = IntentFilter("com.ant.proxy.STATUS")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(statusReceiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(statusReceiver, filter)
        }
    }

    override fun onStop() {
        super.onStop()
        try {
            unregisterReceiver(statusReceiver)
        } catch (_: Exception) {
        }
    }

    private fun importConfigFromUri(uri: Uri) {
        try {
            try {
                contentResolver.takePersistableUriPermission(
                    uri, Intent.FLAG_GRANT_READ_URI_PERMISSION
                )
            } catch (_: SecurityException) {
            }

            val displayName = queryDisplayName(uri) ?: "config.yaml"
            val dest = File(filesDir, AntProcessManager.CONFIG_NAME)

            contentResolver.openInputStream(uri)?.use { input ->
                FileOutputStream(dest).use { output ->
                    input.copyTo(output)
                }
            } ?: throw IllegalStateException("cannot open input stream")

            getSharedPreferences("ant", MODE_PRIVATE)
                .edit()
                .putString("config_display_name", displayName)
                .apply()

            Toast.makeText(
                this,
                getString(R.string.config_import_ok),
                Toast.LENGTH_LONG
            ).show()
            refreshConfigStatus()
        } catch (e: Exception) {
            Toast.makeText(
                this,
                getString(R.string.config_import_fail, e.message ?: "unknown"),
                Toast.LENGTH_LONG
            ).show()
        }
    }

    private fun queryDisplayName(uri: Uri): String? {
        contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
            ?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (idx >= 0) return cursor.getString(idx)
                }
            }
        return uri.lastPathSegment
    }

    private fun refreshConfigStatus() {
        val cfg = File(filesDir, AntProcessManager.CONFIG_NAME)
        if (!cfg.exists() || cfg.length() == 0L) {
            binding.configStatus.setText(R.string.config_none)
            return
        }
        val name = getSharedPreferences("ant", MODE_PRIVATE)
            .getString("config_display_name", cfg.name) ?: cfg.name
        binding.configStatus.text = getString(R.string.config_loaded, name, cfg.length())
    }

    private fun prepareAndStart() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            startVpnService()
        }
    }

    private fun startVpnService() {
        val i = Intent(this, AntVpnService::class.java).apply {
            action = AntVpnService.ACTION_START
        }
        ContextCompat.startForegroundService(this, i)
        binding.statusText.setText(R.string.status_starting)
        binding.btnToggle.isEnabled = false
        handler.postDelayed({ updateUi() }, 500)
    }

    private fun stopVpnService() {
        val i = Intent(this, AntVpnService::class.java).apply {
            action = AntVpnService.ACTION_STOP
        }
        startService(i)
        updateUi()
    }

    private fun updateUi() {
        val running = AntVpnService.isRunning
        binding.statusText.setText(
            if (running) R.string.status_running else R.string.status_stopped
        )
        binding.statusText.setTextColor(
            ContextCompat.getColor(
                this,
                if (running) R.color.status_running else R.color.status_stopped
            )
        )
        if (running) {
            binding.btnToggle.setText(R.string.toggle_stop)
            binding.btnToggle.setIconResource(R.drawable.ic_stop)
            binding.btnToggle.backgroundTintList = ColorStateList.valueOf(
                ContextCompat.getColor(this, R.color.toggle_running)
            )
        } else {
            binding.btnToggle.setText(R.string.toggle_start)
            binding.btnToggle.setIconResource(R.drawable.ic_power)
            binding.btnToggle.backgroundTintList = ColorStateList.valueOf(
                ContextCompat.getColor(this, R.color.toggle_idle)
            )
        }
        binding.btnToggle.isEnabled = true
        refreshConfigStatus()
    }
}
