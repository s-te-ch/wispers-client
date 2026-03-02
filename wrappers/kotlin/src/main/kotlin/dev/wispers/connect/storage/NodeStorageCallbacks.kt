package dev.wispers.connect.storage

import com.sun.jna.Pointer
import dev.wispers.connect.internal.NativeCallbacks
import dev.wispers.connect.internal.NativeTypes
import dev.wispers.connect.types.WispersStatus

/**
 * Interface for providing persistent storage to wispers-connect.
 *
 * Implement this interface to persist node state (root key and registration).
 * On Android, use EncryptedSharedPreferences or Android Keystore for security.
 *
 * All methods are called synchronously from native code and must not block
 * for extended periods.
 *
 * Example implementation:
 * ```kotlin
 * class SecureStorage(private val prefs: SharedPreferences) : NodeStorageCallbacks {
 *     override fun loadRootKey(): ByteArray? {
 *         return prefs.getString("root_key", null)?.let { Base64.decode(it, Base64.DEFAULT) }
 *     }
 *
 *     override fun saveRootKey(key: ByteArray) {
 *         prefs.edit().putString("root_key", Base64.encodeToString(key, Base64.DEFAULT)).apply()
 *     }
 *
 *     override fun deleteRootKey() {
 *         prefs.edit().remove("root_key").apply()
 *     }
 *
 *     override fun loadRegistration(): ByteArray? {
 *         return prefs.getString("registration", null)?.let { Base64.decode(it, Base64.DEFAULT) }
 *     }
 *
 *     override fun saveRegistration(data: ByteArray) {
 *         prefs.edit().putString("registration", Base64.encodeToString(data, Base64.DEFAULT)).apply()
 *     }
 *
 *     override fun deleteRegistration() {
 *         prefs.edit().remove("registration").apply()
 *     }
 * }
 * ```
 */
interface NodeStorageCallbacks {
    /**
     * Load the root key from storage.
     *
     * @return The 32-byte root key, or null if not stored
     */
    fun loadRootKey(): ByteArray?

    /**
     * Save the root key to storage.
     *
     * @param key The 32-byte root key to save
     */
    fun saveRootKey(key: ByteArray)

    /**
     * Delete the root key from storage.
     */
    fun deleteRootKey()

    /**
     * Load registration data from storage.
     *
     * @return The serialized registration data (protobuf format, see storage.proto), or null if not stored
     */
    fun loadRegistration(): ByteArray?

    /**
     * Save registration data to storage.
     *
     * @param data The serialized registration data (protobuf format, see storage.proto)
     */
    fun saveRegistration(data: ByteArray)

    /**
     * Delete registration data from storage.
     */
    fun deleteRegistration()
}

/**
 * Convert Kotlin storage callbacks to JNA native callbacks structure.
 *
 * The returned structure holds strong references to the callback lambdas
 * to prevent garbage collection. The caller must keep the returned structure
 * alive for as long as the native code may call the callbacks.
 */
internal fun NodeStorageCallbacks.toNativeCallbacks(): NativeTypes.WispersNodeStorageCallbacks.ByReference {
    val kotlinCallbacks = this

    return NativeTypes.WispersNodeStorageCallbacks.ByReference().apply {
        ctx = null  // We capture the Kotlin object in closures, don't need ctx

        loadRootKey = NativeCallbacks.LoadRootKeyCallback { _, outKey, outKeyLen ->
            try {
                val key = kotlinCallbacks.loadRootKey()
                if (key == null) {
                    WispersStatus.NOT_FOUND.code
                } else if (key.size > outKeyLen.toInt()) {
                    WispersStatus.BUFFER_TOO_SMALL.code
                } else {
                    outKey?.write(0, key, 0, key.size)
                    WispersStatus.SUCCESS.code
                }
            } catch (e: Exception) {
                WispersStatus.STORE_ERROR.code
            }
        }

        saveRootKey = NativeCallbacks.SaveRootKeyCallback { _, key, keyLen ->
            try {
                val bytes = key?.getByteArray(0, keyLen.toInt()) ?: return@SaveRootKeyCallback WispersStatus.NULL_POINTER.code
                kotlinCallbacks.saveRootKey(bytes)
                WispersStatus.SUCCESS.code
            } catch (e: Exception) {
                WispersStatus.STORE_ERROR.code
            }
        }

        deleteRootKey = NativeCallbacks.DeleteRootKeyCallback { _ ->
            try {
                kotlinCallbacks.deleteRootKey()
                WispersStatus.SUCCESS.code
            } catch (e: Exception) {
                WispersStatus.STORE_ERROR.code
            }
        }

        loadRegistration = NativeCallbacks.LoadRegistrationCallback { _, buffer, bufferLen, outLen ->
            try {
                val data = kotlinCallbacks.loadRegistration()
                if (data == null) {
                    WispersStatus.NOT_FOUND.code
                } else if (data.size > bufferLen.toInt()) {
                    // Write the required size even if buffer is too small
                    outLen?.setLong(0, data.size.toLong())
                    WispersStatus.BUFFER_TOO_SMALL.code
                } else {
                    buffer?.write(0, data, 0, data.size)
                    outLen?.setLong(0, data.size.toLong())
                    WispersStatus.SUCCESS.code
                }
            } catch (e: Exception) {
                WispersStatus.STORE_ERROR.code
            }
        }

        saveRegistration = NativeCallbacks.SaveRegistrationCallback { _, buffer, bufferLen ->
            try {
                val bytes = buffer?.getByteArray(0, bufferLen.toInt()) ?: return@SaveRegistrationCallback WispersStatus.NULL_POINTER.code
                kotlinCallbacks.saveRegistration(bytes)
                WispersStatus.SUCCESS.code
            } catch (e: Exception) {
                WispersStatus.STORE_ERROR.code
            }
        }

        deleteRegistration = NativeCallbacks.DeleteRegistrationCallback { _ ->
            try {
                kotlinCallbacks.deleteRegistration()
                WispersStatus.SUCCESS.code
            } catch (e: Exception) {
                WispersStatus.STORE_ERROR.code
            }
        }
    }
}
