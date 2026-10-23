self.addEventListener("install", () => self.skipWaiting());

self.addEventListener("push", (event) => {
	const { title = "web-push", body, url = "/", tag } = event.data?.json() ?? {};
	event.waitUntil(
		Promise.all([
			self.registration.showNotification(title, { body, tag, data: { url } }),
			// Lets the demo button report the arrival as well as the send.
			self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((pages) => {
				for (const page of pages) {
					page.postMessage({ type: "push-demo:received" });
				}
			}),
		]),
	);
});

self.addEventListener("notificationclick", (event) => {
	event.notification.close();
	event.waitUntil(self.clients.openWindow(event.notification.data?.url ?? "/"));
});
