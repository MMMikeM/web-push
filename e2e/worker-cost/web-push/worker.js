import webpush from "web-push";

export default {
	async fetch(request, env) {
		const subscription = await request.json();
		webpush.setVapidDetails("mailto:push@example.com", env.VAPID_PUBLIC_KEY, env.VAPID_PRIVATE_KEY);
		await webpush.sendNotification(subscription, JSON.stringify({ title: "Hello" }));
		return new Response("ok");
	},
};
