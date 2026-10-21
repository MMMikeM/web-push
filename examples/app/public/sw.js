self.addEventListener("push", (event) => {
	const { title, body, url, tag } = event.data.json();
	event.waitUntil(
		self.registration.showNotification(title, { body, tag, data: { url } }),
	);
});

self.addEventListener("notificationclick", (event) => {
	event.notification.close();
	const url = event.notification.data?.url;
	if (!url) return;

	event.waitUntil(
		self.clients
			.matchAll({ type: "window", includeUncontrolled: true })
			.then((clients) => {
				const target = new URL(url, self.location.origin);
				const open =
					clients.find((client) => client.url === target.href) ??
					clients.find(
						(client) => new URL(client.url).pathname === target.pathname,
					);
				return open ? open.focus() : self.clients.openWindow(target.href);
			}),
	);
});
