package dev.wispers.connect

import dev.wispers.connect.types.*
import org.junit.Assert.*
import org.junit.Test

class TypesTest {

    @Test
    fun `WispersStatus fromCode returns correct status`() {
        assertEquals(WispersStatus.SUCCESS, WispersStatus.fromCode(0))
        assertEquals(WispersStatus.NULL_POINTER, WispersStatus.fromCode(1))
        assertEquals(WispersStatus.HUB_ERROR, WispersStatus.fromCode(12))
        assertEquals(WispersStatus.INVALID_STATE, WispersStatus.fromCode(15))
    }

    @Test
    fun `WispersStatus fromCode throws on unknown code`() {
        assertThrows(IllegalArgumentException::class.java) {
            WispersStatus.fromCode(999)
        }
    }

    @Test
    fun `NodeState fromCode returns correct state`() {
        assertEquals(NodeState.Pending, NodeState.fromCode(0))
        assertEquals(NodeState.Registered, NodeState.fromCode(1))
        assertEquals(NodeState.Activated, NodeState.fromCode(2))
    }

    @Test
    fun `NodeState fromCode throws on unknown code`() {
        assertThrows(IllegalArgumentException::class.java) {
            NodeState.fromCode(99)
        }
    }

    @Test
    fun `ActivationStatus fromCode returns correct status`() {
        assertEquals(ActivationStatus.UNKNOWN, ActivationStatus.fromCode(0))
        assertEquals(ActivationStatus.NOT_ACTIVATED, ActivationStatus.fromCode(1))
        assertEquals(ActivationStatus.ACTIVATED, ActivationStatus.fromCode(2))
    }

    @Test
    fun `ActivationStatus fromCode returns UNKNOWN for invalid code`() {
        assertEquals(ActivationStatus.UNKNOWN, ActivationStatus.fromCode(99))
    }

    @Test
    fun `WispersException fromStatus creates correct exception types`() {
        assertTrue(WispersException.fromStatus(1) is WispersException.NullPointer)
        assertTrue(WispersException.fromStatus(2) is WispersException.InvalidUtf8)
        assertTrue(WispersException.fromStatus(3) is WispersException.StoreError)
        assertTrue(WispersException.fromStatus(4) is WispersException.AlreadyRegistered)
        assertTrue(WispersException.fromStatus(5) is WispersException.NotRegistered)
        assertTrue(WispersException.fromStatus(7) is WispersException.NotFound)
        assertTrue(WispersException.fromStatus(10) is WispersException.InvalidActivationCode)
        assertTrue(WispersException.fromStatus(11) is WispersException.ActivationFailed)
        assertTrue(WispersException.fromStatus(12) is WispersException.HubError)
        assertTrue(WispersException.fromStatus(13) is WispersException.ConnectionFailed)
        assertTrue(WispersException.fromStatus(14) is WispersException.Timeout)
        assertTrue(WispersException.fromStatus(15) is WispersException.InvalidState)
    }

    @Test
    fun `WispersException fromStatus throws on SUCCESS`() {
        assertThrows(IllegalArgumentException::class.java) {
            WispersException.fromStatus(WispersStatus.SUCCESS)
        }
    }

    @Test
    fun `WispersException contains correct status`() {
        val exception = WispersException.fromStatus(WispersStatus.HUB_ERROR)
        assertEquals(WispersStatus.HUB_ERROR, exception.status)
    }

    @Test
    fun `NodeInfo data class works correctly`() {
        val info = NodeInfo(
            nodeNumber = 1,
            name = "Test Node",
            isSelf = true,
            activationStatus = ActivationStatus.ACTIVATED,
            lastSeenAtMillis = 1234567890L,
            isOnline = true
        )

        assertEquals(1, info.nodeNumber)
        assertEquals("Test Node", info.name)
        assertTrue(info.isSelf)
        assertEquals(ActivationStatus.ACTIVATED, info.activationStatus)
        assertEquals(1234567890L, info.lastSeenAtMillis)
        assertTrue(info.isOnline)
    }

    @Test
    fun `RegistrationInfo data class works correctly`() {
        val info = RegistrationInfo(
            connectivityGroupId = "test-group-id",
            nodeNumber = 42
        )

        assertEquals("test-group-id", info.connectivityGroupId)
        assertEquals(42, info.nodeNumber)
    }

    @Test
    fun `NodeState sealed class enables exhaustive when`() {
        val state: NodeState = NodeState.Registered

        val result = when (state) {
            NodeState.Pending -> "pending"
            NodeState.Registered -> "registered"
            NodeState.Activated -> "activated"
        }

        assertEquals("registered", result)
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
