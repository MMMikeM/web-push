import {
	getCurrentSubscription,
	getNotificationPermission,
	isPushSupported,
	removeSubscriptionFromServer,
	sendSubscriptionToServer,
	subscribe,
	unsubscribe,
} from "@mmmike/web-push/client";

const button = document.querySelector("#toggle");
const status = document.querySelector("#status");

const showState = async () => {
	button.textContent = (await getCurrentSubscription())
		? "Turn off notifications"
		: "Turn on notifications";
	button.hidden = false;
};

const turnOn = async () => {
	const result = await subscribe(publicKey);
	if (result.status === "subscribed") {
		await sendSubscriptionToServer(result.subscription);
		status.textContent = "";
	} else {
		status.textContent =
			result.status === "denied"
				? "Notifications are blocked for this site."
				: "This browser can't receive push notifications.";
	}
};

const turnOff = async () => {
	const endpoint = await unsubscribe();
	if (endpoint) {
		await removeSubscriptionFromServer(endpoint);
	}
};

if (!isPushSupported()) {
	status.textContent = "This browser can't receive push notifications.";
	throw new Error("Push is not supported");
}

// Registered on load, so `subscribe`'s permission prompt doesn't wait on it.
await navigator.serviceWorker.register("/sw.js");
const { publicKey } = await (await fetch("/api/vapid-public-key")).json();

const showError = (error) => {
	status.textContent = `Something went wrong: ${error.message}`;
};

// For a visitor already subscribed, subscribe doesn't prompt. Running it on
// every visit replaces a subscription bound to a rotated key, and the upload is
// an upsert, so the server always holds the current one.
if (
	getNotificationPermission() === "granted" &&
	(await getCurrentSubscription())
) {
	await turnOn().catch(showError);
}
await showState();

button.addEventListener("click", async () => {
	button.disabled = true;
	try {
		await ((await getCurrentSubscription()) ? turnOff() : turnOn());
	} catch (error) {
		showError(error);
	} finally {
		await showState();
		button.disabled = false;
	}
});
