package dev.wispers.connect.types

/**
 * TTL profile for activation codes. Mirrors the C enum WispersTtlProfile.
 *
 * Selects the generated code's entropy and validity window. The longer-lived
 * profile is paid for with a longer code (more entropy), so it stays safe
 * against offline brute-force over the wider window.
 */
enum class TtlProfile(val code: Int) {
    /** Short-lived code for live, at-the-keyboard entry (the default). */
    INTERACTIVE(0),

    /** Long-lived code for out-of-band delivery, e.g. email. */
    ASYNCHRONOUS(1),
}
