import { sendPushNotification } from "@mmmike/web-push/send";

export default {
	async fetch(request, env) {
		const subscription = await request.json();
		await sendPushNotification(
			subscription,
			{ title: "Hello" },
			{
				publicKey: env.VAPID_PUBLIC_KEY,
				privateKey: env.VAPID_PRIVATE_KEY,
				subject: "mailto:push@example.com",
			},
		);
		return new Response("ok");
	},
};
