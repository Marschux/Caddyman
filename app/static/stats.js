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
	let open = null;

	function show(name) {
		open = name;
		for (const tile of body.querySelectorAll(".tile")) tile.setAttribute("aria-expanded", String(tile.dataset.panel === name));
		for (const panel of body.querySelectorAll(".panel")) panel.hidden = panel.dataset.panel !== name;
	}

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
		show(open);
	}

	body.addEventListener("click", (event) => {
		const button = event.target.closest("button");
		if (!button) return;
		if (button.dataset.span) {
			span = button.dataset.span;
			store((kept) => kept.setItem(SPAN, span));
			load();
		} else if (button.dataset.panel) {
			show(open === button.dataset.panel ? null : button.dataset.panel);
		} else if (button.dataset.route) {
			// Into the search of the list below, which filters as it is typed in.
			const search = document.querySelector('#route-filter input[name="q"]');
			if (!search) return;
			search.value = button.dataset.route;
			search.dispatchEvent(new Event("input", { bubbles: true }));
			search.scrollIntoView({ behavior: "smooth", block: "center" });
		}
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
