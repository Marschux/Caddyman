// Statistics above the route list: fetched after the page, and again every minute while they are open
// and the tab is in view. Time range and folded state are kept in this browser.
(() => {
	const box = document.getElementById("stats");
	if (!box) return;
	const body = box.querySelector(".stats-body");
	const SPAN = "caddyman.stats.span";
	const SHUT = "caddyman.stats.folded";
	// Without storage (private window, blocked site data) it opens with 24h, unfolded.
	const store = (action) => {
		try {
			return action(localStorage);
		} catch (error) {
			return null;
		}
	};
	let span = store((kept) => kept.getItem(SPAN)) || "24h";

	async function load() {
		if (!box.open || document.hidden) return;
		try {
			const response = await fetch(`/stats/tiles?span=${encodeURIComponent(span)}`);
			// A redirect means the session ended: let the browser show the login.
			if (response.redirected) return location.reload();
			if (!response.ok) return;
			body.innerHTML = await response.text();
		} catch {
			return; // offline for a moment, the next round tries again
		}
	}

	body.addEventListener("click", (event) => {
		const button = event.target.closest("button[data-span]");
		if (!button) return;
		span = button.dataset.span;
		store((kept) => kept.setItem(SPAN, span));
		load();
	});

	if (store((kept) => kept.getItem(SHUT)) === "1") box.open = false;
	box.addEventListener("toggle", () => {
		store((kept) => (box.open ? kept.removeItem(SHUT) : kept.setItem(SHUT, "1")));
		load();
	});
	document.addEventListener("visibilitychange", load);
	load();
	setInterval(load, 60 * 1000);
})();
