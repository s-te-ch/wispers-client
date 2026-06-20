package dev.wispers.connect

import dev.wispers.connect.types.*
import org.junit.Assert.*
import org.junit.Test

class TypesTest {

    @Test
    fun `WispersStatus fromCode returns correct status`() {
        assertEquals(WispersStatus.SUCCESS, WispersStatus.fromCode(0))
        assertEquals(WispersStatus.NULL_POINTER, WispersStatus.fromCode(1))
        assertEquals(WispersStatus.HUB_ERROR, WispersStatus.fromCode(11))
        assertEquals(WispersStatus.INVALID_STATE, WispersStatus.fromCode(14))
        assertEquals(WispersStatus.REVOKED, WispersStatus.fromCode(18))
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
        assertEquals(NodeState.Revoked, NodeState.fromCode(3))
    }

    @Test
    fun `NodeState fromCode throws on unknown code`() {
        assertThrows(IllegalArgumentException::class.java) {
            NodeState.fromCode(99)
        }
    }

    @Test
    fun `WispersException fromStatus creates correct exception types`() {
        assertTrue(WispersException.fromStatus(1) is WispersException.NullPointer)
        assertTrue(WispersException.fromStatus(2) is WispersException.InvalidUtf8)
        assertTrue(WispersException.fromStatus(3) is WispersException.StoreError)
        assertTrue(WispersException.fromStatus(4) is WispersException.AlreadyRegistered)
        assertTrue(WispersException.fromStatus(5) is WispersException.NotRegistered)
        assertTrue(WispersException.fromStatus(6) is WispersException.NotFound)
        assertTrue(WispersException.fromStatus(9) is WispersException.InvalidActivationCode)
        assertTrue(WispersException.fromStatus(10) is WispersException.ActivationFailed)
        assertTrue(WispersException.fromStatus(11) is WispersException.HubError)
        assertTrue(WispersException.fromStatus(12) is WispersException.ConnectionFailed)
        assertTrue(WispersException.fromStatus(13) is WispersException.Timeout)
        assertTrue(WispersException.fromStatus(14) is WispersException.InvalidState)
        assertTrue(WispersException.fromStatus(15) is WispersException.Unauthenticated)
        assertTrue(WispersException.fromStatus(18) is WispersException.Revoked)
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
            metadata = "{\"platform\":\"test\"}",
            isSelf = true,
            state = NodeState.Activated,
            lastSeenAtMillis = 1234567890L,
            isOnline = true
        )

        assertEquals(1, info.nodeNumber)
        assertEquals("Test Node", info.name)
        assertEquals("{\"platform\":\"test\"}", info.metadata)
        assertTrue(info.isSelf)
        assertEquals(NodeState.Activated, info.state)
        assertEquals(1234567890L, info.lastSeenAtMillis)
        assertTrue(info.isOnline)
    }

    @Test
    fun `RegistrationInfo data class works correctly`() {
        val info = RegistrationInfo(
            connectivityGroupId = "test-group-id",
            nodeNumber = 42,
            attestationJwt = "test-jwt"
        )

        assertEquals("test-group-id", info.connectivityGroupId)
        assertEquals(42, info.nodeNumber)
        assertEquals("test-jwt", info.attestationJwt)
    }

    @Test
    fun `NodeState sealed class enables exhaustive when`() {
        val state: NodeState = NodeState.Registered

        val result = when (state) {
            NodeState.Pending -> "pending"
            NodeState.Registered -> "registered"
            NodeState.Activated -> "activated"
            NodeState.Revoked -> "revoked"
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
