---
title: Rotate VAPID keys
description: Replace your VAPID key pair without losing the subscribers created with the old one.
sidebar:
  order: 4
---

Each subscription is bound to the VAPID public key it was created with. A push signed with any other key is refused, usually with a 401 or 403, so replacing your key pair in one step cuts off every existing subscriber until they visit again.

## What `subscribe` does for you

When a visitor comes back, [`subscribe`](/web-push/reference/client/#subscribe) compares the existing subscription's key with the one you pass. If they differ, it unsubscribes the stale subscription and creates a new one, reporting `isNew: true`. Upload the result as you always do, and the server has the new subscription. That's why the [tutorial](/web-push/tutorial/) runs `subscribe` on every visit for a visitor who is already subscribed.

Subscribers who don't come back are the problem: they keep subscriptions bound to the old key.

## Rotating without dropping anyone

1. **Record the key with each subscription.** When saving a subscription, store the public key the page subscribed with alongside it.
2. **Generate the new pair and serve the new public key.** Pages that load from now on subscribe, or resubscribe, with it.
3. **Keep the old pair for sending.** When pushing, sign each subscription with the key pair it was recorded with:

   ```ts
   const vapidFor = (record: StoredSubscription) =>
   	record.publicKey === oldVapid.publicKey ? oldVapid : newVapid;

   await sendPushNotification(record.subscription, payload, vapidFor(record));
   ```

4. **Retire the old pair** once few subscriptions still use it. Delete those that remain, or let them fail with a 401 or 403 and delete them then.

## The gap

Some browsers don't report which key a subscription was created with (`subscription.options.applicationServerKey` is `null`). With nothing to compare, `subscribe` keeps the existing subscription, so it stays on the old key even after the visitor returns. Those subscriptions only move when the old pair is retired: a 401 or 403 after rotating means this is what happened, though nothing in the error says so.
