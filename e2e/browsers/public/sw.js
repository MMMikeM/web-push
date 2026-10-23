self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

// The message goes back to the page before the notification is shown, so a
// browser that can't show one headless still reports the delivery. A
// `userVisibleOnly` push still has to show one, hence both.
self.addEventListener("push", (event) => {
	event.waitUntil(
		(async () => {
			const text = event.data?.text() ?? "";
			const pages = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
			for (const page of pages) {
				// Client.postMessage has no targetOrigin; that's window.postMessage.
				// oxlint-disable-next-line unicorn/require-post-message-target-origin
				page.postMessage(text);
			}
			await self.registration.showNotification("web-push e2e", { body: text });
		})(),
	);
});
