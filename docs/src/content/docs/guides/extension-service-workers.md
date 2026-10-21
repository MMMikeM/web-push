---
title: Extension service workers
description: Subscribe from a Chrome extension's service worker, including silent pushes with userVisibleOnly false.
sidebar:
  order: 6
---

Chrome 121+ lets an extension's service worker subscribe without promising a visible notification for every push. A service worker can't show a permission prompt, so pass its own registration, and the notification permission it already holds decides between `subscribed` and `denied`:

```ts
import { subscribe, sendSubscriptionToServer } from "@mmmike/web-push/client";

const result = await subscribe(vapidPublicKey, {
	registration: self.registration,
	userVisibleOnly: false,
});
if (result.status === "subscribed") {
	await sendSubscriptionToServer(
		result.subscription,
		"https://api.example.com/push/subscribe",
		{
			headers: { Authorization: `Bearer ${token}` },
		},
	);
}
```

[`getCurrentSubscription`](/web-push/reference/client/#getcurrentsubscription) and [`unsubscribe`](/web-push/reference/client/#unsubscribe) take the same `{ registration }` option. Given one, each makes its own support check, so skip `isPushSupported()`, which looks for a page's service worker.

## Rules

- **Declare the `notifications` permission** in the manifest. Chrome refuses push without it, even with `userVisibleOnly: false`.
- **Subscribe from the service worker only.** Chrome rejects `userVisibleOnly: false` from any page, extension pages included. A popup calling `subscribe(vapidPublicKey)` with the default `true` replaces the worker's subscription, and its endpoint, every time; read it there with `getCurrentSubscription()` instead.
- **Use absolute server URLs.** A relative one resolves against `chrome-extension://<id>/`. Hosts listed in the extension's `host_permissions` skip CORS.
- **Send silent pushes to these subscriptions only.** A push to a `userVisibleOnly: true` subscription must show a notification: Chrome shows a generic one in its place, and Safari revokes the permission after repeated pushes that show nothing.
