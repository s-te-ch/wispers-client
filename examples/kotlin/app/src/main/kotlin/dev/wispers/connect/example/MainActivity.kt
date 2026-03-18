package dev.wispers.connect.example

import android.annotation.SuppressLint
import android.os.Bundle
import android.view.View
import android.webkit.WebView
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import dev.wispers.connect.WispersConnect
import dev.wispers.connect.handles.Node
import dev.wispers.connect.handles.ServingSession
import dev.wispers.connect.handles.Storage
import dev.wispers.connect.types.NodeState
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var storage: Storage
    private var node: Node? = null
    private var session: ServingSession? = null
    private var eventLoopJob: Job? = null
    private var connectionManager: QuicConnectionManager? = null

    // Views
    private lateinit var registerView: LinearLayout
    private lateinit var activateView: LinearLayout
    private lateinit var webviewContainer: LinearLayout
    private lateinit var loadingOverlay: FrameLayout
    private lateinit var loadingText: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Find views
        registerView = findViewById(R.id.registerView)
        activateView = findViewById(R.id.activateView)
        webviewContainer = findViewById(R.id.webviewContainer)
        loadingOverlay = findViewById(R.id.loadingOverlay)
        loadingText = findViewById(R.id.loadingText)

        setupRegisterView()
        setupActivateView()
        setupWebView()

        // Initialize
        lifecycleScope.launch {
            initialize()
        }
    }

    private suspend fun initialize() {
        showLoading("Initializing...")

        try {
            storage = WispersConnect.createStorage(applicationContext)
            storage.overrideHubAddr("https://hub.connect.wispers.dev")
            val (restoredNode, state) = storage.restoreOrInit()
            node = restoredNode

            hideLoading()
            showStateView(state)
        } catch (e: Exception) {
            hideLoading()
            Toast.makeText(this, "Init failed: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun showStateView(state: NodeState) {
        registerView.visibility = View.GONE
        activateView.visibility = View.GONE
        webviewContainer.visibility = View.GONE

        when (state) {
            NodeState.Pending -> registerView.visibility = View.VISIBLE
            NodeState.Registered -> activateView.visibility = View.VISIBLE
            NodeState.Activated -> {
                webviewContainer.visibility = View.VISIBLE
                lifecycleScope.launch { startServingAndBrowse() }
            }
        }
    }

    // =========================================================================
    // Registration
    // =========================================================================

    private fun setupRegisterView() {
        val tokenInput = findViewById<EditText>(R.id.tokenInput)
        val registerButton = findViewById<Button>(R.id.registerButton)
        val registerStatus = findViewById<TextView>(R.id.registerStatus)

        registerButton.setOnClickListener {
            val token = tokenInput.text.toString().trim()
            if (token.isEmpty()) {
                registerStatus.text = "Please enter a token"
                return@setOnClickListener
            }

            registerButton.isEnabled = false
            registerStatus.text = ""

            lifecycleScope.launch {
                try {
                    showLoading("Registering...")
                    node!!.register(token)
                    hideLoading()
                    showStateView(NodeState.Registered)
                } catch (e: Exception) {
                    hideLoading()
                    registerButton.isEnabled = true
                    registerStatus.text = "Registration failed: ${e.message}"
                }
            }
        }
    }

    // =========================================================================
    // Activation
    // =========================================================================

    private fun setupActivateView() {
        val activationCodeInput = findViewById<EditText>(R.id.activationCodeInput)
        val activateButton = findViewById<Button>(R.id.activateButton)
        val activateStatus = findViewById<TextView>(R.id.activateStatus)

        activateButton.setOnClickListener {
            val code = activationCodeInput.text.toString().trim()
            if (code.isEmpty()) {
                activateStatus.text = "Please enter an activation code"
                return@setOnClickListener
            }

            activateButton.isEnabled = false
            activateStatus.text = ""

            lifecycleScope.launch {
                try {
                    showLoading("Activating...")
                    node!!.activate(code)
                    hideLoading()
                    showStateView(NodeState.Activated)
                } catch (e: Exception) {
                    hideLoading()
                    activateButton.isEnabled = true
                    activateStatus.text = "Activation failed: ${e.message}"
                }
            }
        }
    }

    // =========================================================================
    // WebView + serving
    // =========================================================================

    @SuppressLint("SetJavaScriptEnabled")
    private fun setupWebView() {
        val webView = findViewById<WebView>(R.id.webView)
        val reloadButton = findViewById<Button>(R.id.reloadButton)

        webView.settings.javaScriptEnabled = true
        webView.settings.domStorageEnabled = true

        reloadButton.setOnClickListener {
            webView.reload()
        }
    }

    private suspend fun startServingAndBrowse() {
        val connectionStatus = findViewById<TextView>(R.id.connectionStatus)
        val webView = findViewById<WebView>(R.id.webView)

        showLoading("Starting serving session...")

        try {
            val servingSession = node!!.startServing()
            session = servingSession

            // Run event loop in background
            eventLoopJob = lifecycleScope.launch {
                try {
                    servingSession.runEventLoop()
                } catch (e: Exception) {
                    runOnUiThread {
                        connectionStatus.text = "Event loop ended: ${e.message}"
                    }
                }
            }

            hideLoading()
            showLoading("Connecting to peer...")

            // Set up connection manager and WebView client
            val manager = QuicConnectionManager(node!!)
            connectionManager = manager

            val client = QuicWebViewClient(
                connectionManager = manager,
                onError = { msg ->
                    runOnUiThread {
                        connectionStatus.text = msg
                    }
                }
            )

            runOnUiThread {
                webView.webViewClient = client
                connectionStatus.text = "Connected"
            }

            hideLoading()

            // Load the target page
            runOnUiThread {
                webView.loadUrl("http://1.wispers.link:8000/3d.html")
            }
        } catch (e: Exception) {
            hideLoading()
            runOnUiThread {
                connectionStatus.text = "Failed: ${e.message}"
            }
        }
    }

    // =========================================================================
    // Loading overlay
    // =========================================================================

    private fun showLoading(text: String) {
        runOnUiThread {
            loadingText.text = text
            loadingOverlay.visibility = View.VISIBLE
        }
    }

    private fun hideLoading() {
        runOnUiThread {
            loadingOverlay.visibility = View.GONE
        }
    }

    // =========================================================================
    // Lifecycle
    // =========================================================================

    override fun onDestroy() {
        super.onDestroy()

        connectionManager?.close()
        eventLoopJob?.cancel()

        session?.close()
        node?.close()

        if (::storage.isInitialized) {
            storage.close()
        }
    }
}
