self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

// The message goes back to the page before the notification is shown, so a
// browser that can't show one headless still reports the delivery. Chrome
// revokes a subscription whose pushes never show a notification, hence both.
self.addEventListener("push", (event) => {
	event.waitUntil(
		(async () => {
			const text = event.data?.text() ?? "";
			const pages = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
			for (const page of pages) {
				page.postMessage(text);
			}
			await self.registration.showNotification("web-push e2e", { body: text });
		})(),
	);
});
