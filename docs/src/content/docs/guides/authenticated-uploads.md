---
title: Authenticated uploads
description: Send the subscription to a server that needs to know who is subscribing, with a token or cookies, same-origin or cross-origin.
sidebar:
  order: 5
---

To push to one person rather than everyone, the server has to know whose subscription it's saving. The upload helpers take a third argument for that: a `RequestInit` merged into the request.

## Same origin, with cookies

`fetch` sends cookies to your own origin by default, so a session cookie already identifies the user:

```ts
await sendSubscriptionToServer(result.subscription);
```

The server reads the session as it would for any other request, and stores the subscription under that user.

## With a token

Pass the header in `init`. Headers merge with the `Content-Type: application/json` the helper sets:

```ts
await sendSubscriptionToServer(
	result.subscription,
	"https://api.example.com/push/subscribe",
	{
		headers: { Authorization: `Bearer ${token}` },
	},
);
```

The body is always the serialized subscription; `init` can't replace it.

## Removing, on a different route or method

[`removeSubscriptionFromServer`](/reference/client/#removesubscriptionfromserver) sends `DELETE` with `{ endpoint }` by default. If your route differs, change the URL and method:

```ts
const endpoint = await unsubscribe();
if (endpoint) {
	await removeSubscriptionFromServer(
		endpoint,
		"https://api.example.com/push/unsubscribe",
		{
			method: "POST",
			headers: { Authorization: `Bearer ${token}` },
		},
	);
}
```

## Cross-origin

A JSON upload to another origin triggers a CORS preflight. The server has to answer the `OPTIONS` request and allow the headers you send:

```http
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Methods: POST, DELETE
Access-Control-Allow-Headers: Content-Type, Authorization
```

To send cookies cross-origin, add `credentials: "include"` to `init` and `Access-Control-Allow-Credentials: true` to the response. An [extension](/guides/extension-service-workers/) calling a host listed in its `host_permissions` skips CORS entirely.

## Storing subscriptions per user

Store subscriptions per user, keyed by endpoint, so one person's phone and laptop are two rows under one user. Pushing to that user is then a [batch](/guides/send-to-many/) over their rows.
