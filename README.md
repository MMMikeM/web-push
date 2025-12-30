# @mmmike/web-push

Zero-dependency Web Push library implementing RFC 8291 for Node.js, Edge runtimes, and browsers.

## Features

- **Zero dependencies** - Uses only Web Crypto API
- **Edge-compatible** - Works in Node.js, Cloudflare Workers, and browsers
- **RFC 8291 compliant** - Standard Web Push protocol
- **TypeScript** - Full type definitions included

## Installation

```bash
npm install @mmmike/web-push
```

## Usage

### Generate VAPID Keys

```typescript
import { generateVapidKeys } from "@mmmike/web-push/vapid";

const { publicKey, privateKey } = await generateVapidKeys();
// Store these securely - publicKey goes to client, privateKey stays on server
```

### Client-Side: Subscribe to Push

```typescript
import { subscribeToPush, sendSubscriptionToServer } from "@mmmike/web-push/client";

// Subscribe user to push notifications
const subscription = await subscribeToPush(vapidPublicKey);

if (subscription) {
  // Send subscription to your server
  await sendSubscriptionToServer(subscription, "/api/push/subscribe");
}
```

### Server-Side: Send Notifications

```typescript
import { sendPushNotification } from "@mmmike/web-push/send";

const success = await sendPushNotification(
  subscription, // PushSubscriptionData from client
  {
    title: "Hello!",
    body: "You have a new message",
    icon: "/icon.png",
    data: { url: "/messages" }
  },
  {
    publicKey: process.env.VAPID_PUBLIC_KEY,
    privateKey: process.env.VAPID_PRIVATE_KEY,
    subject: "mailto:admin@example.com"
  }
);
```

## API Reference

### Client-Side (`@mmmike/web-push/client`)

| Function | Description |
|----------|-------------|
| `isPushSupported()` | Check if push is supported in browser |
| `getNotificationPermission()` | Get current notification permission |
| `requestNotificationPermission()` | Request notification permission |
| `subscribeToPush(vapidPublicKey)` | Subscribe to push notifications |
| `unsubscribeFromPush()` | Unsubscribe from push notifications |
| `getCurrentSubscription()` | Get existing subscription if any |
| `serializeSubscription(sub)` | Convert subscription to JSON-safe format |
| `sendSubscriptionToServer(sub, endpoint)` | POST subscription to your server |
| `removeSubscriptionFromServer(endpoint, serverEndpoint)` | DELETE subscription from server |

### Server-Side (`@mmmike/web-push/send`)

| Function | Description |
|----------|-------------|
| `sendPushNotification(subscription, payload, vapid, options?)` | Send a push notification |

### VAPID Utilities (`@mmmike/web-push/vapid`)

| Function | Description |
|----------|-------------|
| `generateVapidKeys()` | Generate ECDSA P-256 key pair |
| `createVapidJwt(options)` | Create VAPID JWT for authentication |
| `uint8ArrayToUrlBase64(array)` | Encode bytes to URL-safe base64 |
| `urlBase64ToUint8Array(base64)` | Decode URL-safe base64 to bytes |

## Types

```typescript
interface PushPayload {
  title: string;
  body: string;
  icon?: string;
  badge?: string;
  image?: string;
  tag?: string;
  data?: Record<string, unknown>;
  actions?: Array<{ action: string; title: string; icon?: string }>;
  requireInteraction?: boolean;
  silent?: boolean;
  timestamp?: number;
}

interface PushSubscriptionData {
  endpoint: string;
  keys: {
    p256dh: string;
    auth: string;
  };
}

interface VapidConfig {
  publicKey: string;
  privateKey: string;
  subject: string; // mailto: or https: URL
}
```

## License

MIT
