// Generate a VAPID key pair, then load them as Worker secrets:
//   npm run keys            # needs Node 22.18+ / 23.6+ to run .ts directly
//                           # on older Node: rename to .mjs and drop the types
//   npx wrangler secret put VAPID_PUBLIC_KEY
//   npx wrangler secret put VAPID_PRIVATE_KEY
//   npx wrangler secret put VAPID_SUBJECT     # e.g. mailto:you@example.com
import { generateVapidKeys } from "@mmmike/web-push/vapid";

const { publicKey, privateKey } = await generateVapidKeys();

console.log("VAPID_PUBLIC_KEY =", publicKey);
console.log("VAPID_PRIVATE_KEY =", privateKey);
