self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

// Chrome revokes a subscription whose pushes show no notification, so each one
// is shown as well as handed back to the page.
self.addEventListener("push", (event) => {
	event.waitUntil(
		(async () => {
			const text = event.data?.text() ?? "";
			await self.registration.showNotification("web-push e2e", { body: text });
			const pages = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
			for (const page of pages) {
				page.postMessage(text);
			}
		})(),
	);
});
