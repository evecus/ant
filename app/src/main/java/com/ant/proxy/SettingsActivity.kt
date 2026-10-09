package com.ant.proxy

import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.ant.proxy.databinding.ActivitySettingsBinding

class SettingsActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySettingsBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySettingsBinding.inflate(layoutInflater)
        setContentView(binding.root)
        applySystemBarInsets(binding.root)

        val prefs = getSharedPreferences(AntProcessManager.SETTINGS_NAME, MODE_PRIVATE)

        when (prefs.getString(AntProcessManager.KEY_STACK, AntProcessManager.DEFAULT_STACK)) {
            "system" -> binding.rbSystem.isChecked = true
            "mixed" -> binding.rbMixed.isChecked = true
            else -> binding.rbGvisor.isChecked = true
        }
        binding.etMtu.setText(prefs.getInt(AntProcessManager.KEY_MTU, AntProcessManager.TUN_MTU).toString())
        binding.swDnsHijack.isChecked = prefs.getBoolean(AntProcessManager.KEY_DNS_HIJACK, true)
        when (prefs.getString(AntProcessManager.KEY_LOG_LEVEL, "info")) {
            "debug" -> binding.rbDebug.isChecked = true
            "warn" -> binding.rbWarn.isChecked = true
            "error" -> binding.rbError.isChecked = true
            else -> binding.rbInfo.isChecked = true
        }

        binding.btnSave.setOnClickListener {
            val mtu = binding.etMtu.text.toString().toIntOrNull()
            if (mtu == null || mtu < 576 || mtu > 10000) {
                Toast.makeText(this, R.string.settings_mtu_invalid, Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            val stack = when (binding.rgStack.checkedRadioButtonId) {
                R.id.rbSystem -> "system"
                R.id.rbMixed -> "mixed"
                else -> "gvisor"
            }
            val level = when (binding.rgLogLevel.checkedRadioButtonId) {
                R.id.rbDebug -> "debug"
                R.id.rbWarn -> "warn"
                R.id.rbError -> "error"
                else -> "info"
            }
            prefs.edit()
                .putString(AntProcessManager.KEY_STACK, stack)
                .putInt(AntProcessManager.KEY_MTU, mtu)
                .putBoolean(AntProcessManager.KEY_DNS_HIJACK, binding.swDnsHijack.isChecked)
                .putString(AntProcessManager.KEY_LOG_LEVEL, level)
                .apply()
            Toast.makeText(this, R.string.settings_saved, Toast.LENGTH_SHORT).show()
            finish()
        }
    }
}
