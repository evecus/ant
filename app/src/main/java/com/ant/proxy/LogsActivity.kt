package com.ant.proxy

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.appcompat.app.AppCompatActivity
import com.ant.proxy.databinding.ActivityLogsBinding

class LogsActivity : AppCompatActivity() {

    private lateinit var binding: ActivityLogsBinding
    private val handler = Handler(Looper.getMainLooper())

    private val logPoll = object : Runnable {
        override fun run() {
            val newLogs = AntVpnService.consumeLogs()
            if (newLogs.isNotEmpty()) {
                binding.logView.append(newLogs)
                scrollToEnd()
            }
            handler.postDelayed(this, 500)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityLogsBinding.inflate(layoutInflater)
        setContentView(binding.root)
        applySystemBarInsets(binding.root)

        binding.logView.text = AntVpnService.snapshotLogs()
        binding.btnClear.setOnClickListener {
            binding.logView.text = ""
        }
        scrollToEnd()
    }

    private fun scrollToEnd() {
        binding.logView.post {
            (binding.logView.parent as? android.widget.ScrollView)
                ?.fullScroll(android.view.View.FOCUS_DOWN)
        }
    }

    override fun onStart() {
        super.onStart()
        handler.post(logPoll)
    }

    override fun onStop() {
        super.onStop()
        handler.removeCallbacks(logPoll)
    }
}
