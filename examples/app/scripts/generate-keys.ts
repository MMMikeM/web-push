import {
	generateVapidKeys,
	uint8ArrayToUrlBase64,
} from "@mmmike/web-push/vapid";

const { publicKey, privateKey } = await generateVapidKeys();
const adminToken = uint8ArrayToUrlBase64(
	crypto.getRandomValues(new Uint8Array(32)),
);

console.log(`VAPID_PUBLIC_KEY=${publicKey}`);
console.log(`VAPID_PRIVATE_KEY=${privateKey}`);
console.log("VAPID_SUBJECT=mailto:you@example.com");
console.log(`ADMIN_TOKEN=${adminToken}`);
