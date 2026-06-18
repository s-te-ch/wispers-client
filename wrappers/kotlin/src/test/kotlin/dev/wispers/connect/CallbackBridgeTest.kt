package dev.wispers.connect

import com.sun.jna.Pointer
import dev.wispers.connect.internal.CallbackBridge
import dev.wispers.connect.types.WispersException
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test
import kotlin.coroutines.resume

class CallbackBridgeTest {

    @Test
    fun `register returns unique context pointers`() = runTest {
        val contexts = mutableListOf<Pointer>()

        // Register multiple continuations
        repeat(3) {
            suspendCancellableCoroutine { cont: CancellableContinuation<Unit> ->
                val ctx = CallbackBridge.register(cont)
                contexts.add(ctx)
                cont.resume(Unit)
            }
        }

        // All contexts should be unique
        assertEquals(3, contexts.toSet().size)
    }

    @Test
    fun `resumeSuccess completes continuation with value`() = runTest {
        val result = suspendCancellableCoroutine { cont: CancellableContinuation<String> ->
            val ctx = CallbackBridge.register(cont)
            // Simulate callback from native code
            CallbackBridge.resumeSuccess(ctx, "test-value")
        }

        assertEquals("test-value", result)
    }

    @Test
    fun `resumeException completes continuation with error`() = runTest {
        val exception = assertThrows(WispersException.HubError::class.java) {
            kotlinx.coroutines.runBlocking {
                suspendCancellableCoroutine { cont: CancellableContinuation<Unit> ->
                    val ctx = CallbackBridge.register(cont)
                    CallbackBridge.resumeException(ctx, WispersException.HubError("test error"))
                }
            }
        }

        assertEquals("test error", exception.message)
    }

    @Test
    fun `resumeWithStatus resumes with Unit on success`() = runTest {
        val result = suspendCancellableCoroutine { cont: CancellableContinuation<Unit> ->
            val ctx = CallbackBridge.register(cont)
            CallbackBridge.resumeWithStatus(ctx, 0) // SUCCESS = 0
        }

        assertEquals(Unit, result)
    }

    @Test
    fun `resumeWithStatus throws exception on error status`() = runTest {
        val exception = assertThrows(WispersException.HubError::class.java) {
            kotlinx.coroutines.runBlocking {
                suspendCancellableCoroutine { cont: CancellableContinuation<Unit> ->
                    val ctx = CallbackBridge.register(cont)
                    CallbackBridge.resumeWithStatus(ctx, 11) // HUB_ERROR = 11
                }
            }
        }

        assertNotNull(exception)
    }

    @Test
    fun `context pointer encodes numeric ID`() = runTest {
        suspendCancellableCoroutine { cont: CancellableContinuation<Unit> ->
            val ctx = CallbackBridge.register(cont)
            // Context should be a non-null pointer with a positive native value
            val nativeValue = Pointer.nativeValue(ctx)
            assertTrue("Native value should be positive", nativeValue > 0)
            cont.resume(Unit)
        }
    }

    private inline fun <reified T : Throwable> assertThrows(
        expectedType: Class<T>,
        executable: () -> Unit
    ): T {
        try {
            executable()
            fail("Expected ${expectedType.simpleName} to be thrown")
            throw AssertionError("Unreachable")
        } catch (e: Throwable) {
            if (expectedType.isInstance(e)) {
                @Suppress("UNCHECKED_CAST")
                return e as T
            }
            throw e
        }
    }
}
