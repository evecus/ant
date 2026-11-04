package com.ant.proxy

import android.Manifest
import android.content.BroadcastReceiver
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.EditText
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.ant.proxy.databinding.ActivityMainBinding
import com.google.android.material.dialog.MaterialAlertDialogBuilder

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

        binding.btnImport.setOnClickListener { showImportDialog() }

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

    // ------------------------------------------------------------ node import

    private fun showImportDialog() {
        val input = EditText(this).apply {
            hint = getString(R.string.hint_node_links)
            minLines = 4
            setSingleLine(false)
        }
        val pad = (20 * resources.displayMetrics.density).toInt()
        val wrap = android.widget.FrameLayout(this).apply {
            setPadding(pad, pad / 2, pad, 0)
            addView(input)
        }

        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.btn_import)
            .setView(wrap)
            .setPositiveButton(R.string.node_import_btn) { _, _ ->
                doImport(input.text.toString())
            }
            .setNegativeButton(android.R.string.cancel, null)
            .setNeutralButton(R.string.node_clear_btn) { _, _ ->
                ConfigManager.clearNodes(this)
                Toast.makeText(this, R.string.node_clear_ok, Toast.LENGTH_SHORT).show()
                refreshConfigStatus()
            }
            .show()
    }

    private fun doImport(raw: String) {
        if (raw.isBlank()) {
            // 空输入 → 直接尝试剪贴板
            val clip = (getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager)
                ?.primaryClip?.getItemAt(0)?.text?.toString().orEmpty()
            if (clip.isBlank()) {
                Toast.makeText(this, R.string.node_import_none, Toast.LENGTH_SHORT).show()
                return
            }
            importAndReport(clip)
            return
        }
        importAndReport(raw)
    }

    private fun importAndReport(raw: String) {
        val n = try {
            ConfigManager.importNodeLinks(this, raw)
        } catch (e: Exception) {
            Toast.makeText(this, getString(R.string.node_import_fail, e.message ?: ""), Toast.LENGTH_LONG).show()
            return
        }
        if (n > 0) {
            Toast.makeText(this, getString(R.string.node_import_ok, n), Toast.LENGTH_LONG).show()
            refreshConfigStatus()
        } else {
            Toast.makeText(this, R.string.node_import_none, Toast.LENGTH_LONG).show()
        }
    }

    private fun refreshConfigStatus() {
        val n = ConfigManager.nodeCount(this)
        if (n == 0) {
            binding.configStatus.setText(R.string.config_none)
        } else {
            binding.configStatus.text = getString(R.string.config_loaded, n)
        }
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
