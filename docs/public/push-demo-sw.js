self.addEventListener("install", () => self.skipWaiting());

self.addEventListener("push", (event) => {
	const { title = "web-push", body, url = "/", tag } = event.data?.json() ?? {};
	event.waitUntil(
		Promise.all([
			self.registration.showNotification(title, {
				body,
				tag,
				icon: "/apple-touch-icon.png",
				data: { url },
			}),
			// The page mirrors the notification as a toast, for anyone whose
			// system notifications are muted.
			self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((pages) => {
				for (const page of pages) {
					page.postMessage({ type: "push-demo:received", title, body });
				}
			}),
		]),
	);
});

self.addEventListener("notificationclick", (event) => {
	event.notification.close();
	event.waitUntil(self.clients.openWindow(event.notification.data?.url ?? "/"));
});
