/**
 * A subscription that can't be sent to: its endpoint isn't an `https:` URL, or
 * its `p256dh` or `auth` key is missing or malformed. Delete it from your
 * store, since sending it again fails the same way. Mistakes of your own, in
 * the VAPID config, payload size, `topic`, `ttl` or `timeoutMs`, throw a plain
 * `Error` instead.
 *
 * @see {@link https://web-push.thelazyweb.dev/guides/handle-errors/ | Handle errors and retries}
 */
export class InvalidSubscriptionError extends Error {
	/** Always `"InvalidSubscriptionError"`, so it survives serialization and logging */
	override readonly name = "InvalidSubscriptionError";
}
