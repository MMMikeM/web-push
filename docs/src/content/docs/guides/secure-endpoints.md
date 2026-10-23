---
title: Secure your endpoints
description: Keep Web Push subscription endpoints out of your logs, send only to real push service hosts, and guard the server routes that trigger a send.
sidebar:
  order: 7
---

A subscription endpoint is a capability URL: anyone holding it, with the subscription's keys, can send messages to that device until the subscription dies. Two habits follow from that.

## Keep endpoints out of logs

[`WebPushError`](/reference/send/#webpusherror) carries the full endpoint so you can act on it, but its `toJSON` truncates the endpoint and the response body. A structured logger that serializes the error therefore never stores a URL that can push. If you log fields by hand, log `statusCode` and `retryAfterMs`, not `endpoint`.

Treat your subscriptions table the same way you treat session tokens.

## Only push to real push services

The send functions POST to whatever endpoint a subscription names, and the subscription came from a browser. The library rejects endpoints that aren't `https:`, as [RFC 8030 §3](https://www.rfc-editor.org/rfc/rfc8030#section-3) requires, but it can't know which hosts are genuine push services.

If a hostile client registers `https://internal-service.local/hooks` as its "push endpoint", your server becomes a proxy into networks it can reach and the attacker can't. Where that matters, allowlist the real push hosts when you save a subscription:

| Browser                   | Endpoint host                 |
| ------------------------- | ----------------------------- |
| Chrome and other Chromium | `fcm.googleapis.com`          |
| Edge                      | `*.notify.windows.com`        |
| Firefox                   | `*.push.services.mozilla.com` |
| Safari on macOS and iOS   | `*.push.apple.com`            |

[`isPushServiceEndpoint`](/reference/send/#ispushserviceendpoint) checks an endpoint against these hosts, and the [tutorial's server](/tutorial/#4-the-server) uses it when a browser uploads a subscription.

These hosts are as of August 2026. Browsers can change push services, and smaller ones run their own (Samsung Internet, for example), so log the subscriptions you reject rather than dropping them silently.

## Guard the routes that send

A route that pushes to every subscriber is a broadcast channel into your users' notifications. Put it behind real authentication. A secret URL ends up in server logs, browser history, and proxies.
