// Live view: fetches this same page every few seconds and swaps in its rows.
// Before the log is set up there is no table; the page then checks whether one has appeared.
(() => {
	// Set by the page: a Caddy that is only reached over the network is asked less often.
	const INTERVAL = 1000 * Number(document.currentScript.dataset.seconds || 5);
	const live = document.getElementById("live");

	async function refresh() {
		if (document.hidden || (live && !live.checked)) return;
		let fresh;
		try {
			const response = await fetch(location.href, { headers: { Accept: "text/html" } });
			// A redirect means the session ended: let the browser show the login.
			if (response.redirected) return location.reload();
			fresh = new DOMParser().parseFromString(await response.text(), "text/html");
		} catch {
			return; // offline for a moment, the next round tries again
		}
		const rows = document.getElementById("log-entries");
		const next = fresh.getElementById("log-entries");
		if (rows && next) rows.replaceWith(next);
		else if (Boolean(rows) !== Boolean(next)) location.reload();
	}

	setInterval(refresh, INTERVAL);
})();
