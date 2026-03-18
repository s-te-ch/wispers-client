package dev.wispers.connect.example

import android.util.Log
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebViewClient
import dev.wispers.connect.handles.QuicStream
import kotlinx.coroutines.runBlocking
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

/**
 * WebViewClient that tunnels HTTP requests through wispers port forwarding.
 *
 * Uses the wispers FORWARD protocol: each QUIC stream starts with a
 * "FORWARD <port>\n" handshake, then becomes a transparent TCP tunnel
 * to the target port on the peer node.
 *
 * Protocol per stream:
 * 1. Send "FORWARD 80\n"
 * 2. Read response - "OK\n" or "ERROR ...\n"
 * 3. Send raw HTTP/1.1 request bytes
 * 4. Read raw HTTP/1.1 response bytes
 * 5. Stream closes
 */
class QuicWebViewClient(
    private val connectionManager: QuicConnectionManager,
    private val targetHost: String = "1.wispers.link",
    private val onError: (String) -> Unit = {}
) : WebViewClient() {

    override fun shouldInterceptRequest(
        view: android.webkit.WebView?,
        request: WebResourceRequest?
    ): WebResourceResponse? {
        if (request == null) return null

        val url = request.url ?: return null

        // Only intercept requests to our target host
        if (url.host != targetHost) {
            return null
        }

        return try {
            runBlocking {
                tunnelRequest(request)
            }
        } catch (e: Exception) {
            Log.e(TAG, "shouldInterceptRequest FAILED for $url: ${e.javaClass.simpleName}: ${e.message}")
            onError("Request failed: ${e.message}")
            errorResponse(502, "Wispers tunnel error: ${e.message}")
        }
    }

    private suspend fun tunnelRequest(request: WebResourceRequest): WebResourceResponse {
        val url = request.url
        val port = if (url.port != -1) url.port else 80
        Log.d(TAG, "tunnelRequest: ${request.method} $url (port=$port)")

        val stream = connectionManager.openStream()
        Log.d(TAG, "  stream opened")
        try {
            // Port forwarding handshake
            stream.write("FORWARD $port\n".toByteArray())
            Log.d(TAG, "  FORWARD written")

            val handshakeResponse = readLine(stream)
            Log.d(TAG, "  handshake response: '$handshakeResponse'")
            if (handshakeResponse != "OK") {
                val msg = if (handshakeResponse.startsWith("ERROR ")) {
                    handshakeResponse.substring(6)
                } else {
                    "Unexpected handshake response: $handshakeResponse"
                }
                return errorResponse(502, msg)
            }

            // Send HTTP/1.1 request through the tunnel
            val httpRequest = buildHttpRequest(request)
            stream.write(httpRequest)
            Log.d(TAG, "  HTTP request written (${httpRequest.size} bytes)")

            // Signal end of request (send FIN). The server doesn't need
            // the FIN to start responding (it has the full HTTP request at
            // \r\n\r\n), but sending it lets the server know we're done.
            stream.finish()
            Log.d(TAG, "  stream finished (FIN sent)")

            // Read the full HTTP response. Connection: close ensures the
            // server closes its end after responding, which terminates readFully.
            val responseBytes = readFully(stream)
            Log.d(TAG, "  response read: ${responseBytes.size} bytes")

            return parseHttpResponse(responseBytes)
        } catch (e: Exception) {
            Log.e(TAG, "  tunnelRequest FAILED: ${e.javaClass.simpleName}: ${e.message}")
            throw e
        } finally {
            try { stream.close() } catch (_: Exception) {}
        }
    }

    /**
     * Read bytes from the stream until we see a newline, return as a string.
     */
    private suspend fun readLine(stream: QuicStream): String {
        val buffer = ByteArrayOutputStream()
        while (true) {
            val chunk = stream.read(1)
            if (chunk.isEmpty()) break
            if (chunk[0] == '\n'.code.toByte()) break
            buffer.write(chunk)
        }
        return buffer.toByteArray().toString(Charsets.UTF_8)
    }

    private fun buildHttpRequest(request: WebResourceRequest): ByteArray {
        val url = request.url
        val method = request.method ?: "GET"
        val path = url.path.orEmpty().let { if (it.isEmpty()) "/" else it } +
            (url.query?.let { "?$it" } ?: "")

        val sb = StringBuilder()
        sb.append("$method $path HTTP/1.1\r\n")
        sb.append("Host: ${url.host ?: targetHost}\r\n")

        // Forward request headers (except Host which we set above)
        request.requestHeaders?.forEach { (key, value) ->
            if (!key.equals("Host", ignoreCase = true)) {
                sb.append("$key: $value\r\n")
            }
        }

        // Connection: close so the server closes its end after responding,
        // which makes the QUIC stream end so readFully() terminates.
        sb.append("Connection: close\r\n")
        sb.append("\r\n")

        return sb.toString().toByteArray(Charsets.UTF_8)
    }

    private suspend fun readFully(stream: QuicStream): ByteArray {
        val buffer = ByteArrayOutputStream()
        while (true) {
            val chunk = stream.read(8192)
            if (chunk.isEmpty()) break
            buffer.write(chunk)
        }
        return buffer.toByteArray()
    }

    private fun parseHttpResponse(data: ByteArray): WebResourceResponse {
        if (data.isEmpty()) {
            return errorResponse(502, "Empty response from server")
        }

        // Use ISO-8859-1 to preserve bytes exactly (it's a 1:1 byte mapping)
        val raw = String(data, Charsets.ISO_8859_1)

        // Find the header/body boundary
        val headerEnd = raw.indexOf("\r\n\r\n")
        if (headerEnd == -1) {
            return errorResponse(502, "Malformed response: no header boundary")
        }

        val headerSection = raw.substring(0, headerEnd)
        val bodyStartOffset = headerEnd + 4  // Skip \r\n\r\n

        // Parse status line
        val lines = headerSection.split("\r\n")
        if (lines.isEmpty()) {
            return errorResponse(502, "Malformed response: empty headers")
        }

        val statusLine = lines[0]
        val statusParts = statusLine.split(" ", limit = 3)
        if (statusParts.size < 2) {
            return errorResponse(502, "Malformed status line: $statusLine")
        }

        val statusCode = statusParts[1].toIntOrNull() ?: 502
        val reasonPhrase = if (statusParts.size >= 3) statusParts[2] else "Unknown"

        // Parse headers
        val headers = mutableMapOf<String, String>()
        for (i in 1 until lines.size) {
            val colonIdx = lines[i].indexOf(':')
            if (colonIdx > 0) {
                val key = lines[i].substring(0, colonIdx).trim()
                val value = lines[i].substring(colonIdx + 1).trim()
                headers[key] = value
            }
        }

        // Extract content type and encoding
        val contentType = headers.entries
            .firstOrNull { it.key.equals("Content-Type", ignoreCase = true) }
            ?.value ?: "application/octet-stream"

        val mimeType = contentType.split(";")[0].trim()
        val encoding = CHARSET_PATTERN.find(contentType)?.groupValues?.get(1)

        // Body is everything after the header boundary.
        // Since ISO-8859-1 is byte-transparent, bodyStartOffset == byte offset.
        val bodyBytes = data.copyOfRange(bodyStartOffset, data.size)

        return WebResourceResponse(
            mimeType,
            encoding,
            statusCode,
            reasonPhrase,
            headers,
            ByteArrayInputStream(bodyBytes)
        )
    }

    private fun errorResponse(code: Int, message: String): WebResourceResponse {
        return WebResourceResponse(
            "text/plain",
            "UTF-8",
            code,
            message,
            emptyMap(),
            ByteArrayInputStream(message.toByteArray())
        )
    }

    companion object {
        private const val TAG = "WispersHTTP"
        private val CHARSET_PATTERN = Regex("""charset=([^\s;]+)""", RegexOption.IGNORE_CASE)
    }
}
