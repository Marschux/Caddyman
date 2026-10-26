// Stats page: picking a route shows it at once, a click on a column title sorts the table, and
// every minute the page fetches itself and swaps in the new numbers, keeping the sorting.
(() => {
	const filter = document.getElementById("stats-filter");
	// Picking a route or ticking "Errors only" shows it at once.
	if (filter) filter.addEventListener("change", () => filter.submit());
	// Column and direction picked last; nothing picked: the order of the server.
	let sorting = null;

	function sort() {
		const table = document.querySelector("table.sortable");
		if (!table || !sorting) return;
		const [column, descending] = sorting;
		const heads = [...table.tHead.rows[0].cells];
		heads.forEach((head, index) => (index === column ? head.setAttribute("aria-sort", descending ? "descending" : "ascending") : head.removeAttribute("aria-sort")));
		const key = (row) => row.cells[column].dataset.sort || "";
		// Numbers as numbers, the route by its name.
		const rows = [...table.tBodies[0].rows].sort((a, b) => {
			const x = key(a), y = key(b);
			const order = column ? Number(x) - Number(y) : x.localeCompare(y, undefined, { numeric: true });
			return descending ? -order : order;
		});
		table.tBodies[0].append(...rows);
	}

	function prepare() {
		const table = document.querySelector("table.sortable");
		if (!table) return;
		[...table.tHead.rows[0].cells].forEach((head, column) => {
			const button = document.createElement("button");
			button.type = "button";
			button.className = "sort";
			button.textContent = head.textContent;
			head.replaceChildren(button);
			button.addEventListener("click", () => {
				// Numbers start with the largest, the names with A.
				const first = column > 0;
				sorting = sorting && sorting[0] === column ? [column, !sorting[1]] : [column, first];
				sort();
			});
		});
		sort();
	}

	async function refresh() {
		if (document.hidden || document.querySelector("#stats-page[data-still]")) return;
		let fresh;
		try {
			const response = await fetch(location.href);
			// A redirect means the session ended: let the browser show the login.
			if (response.redirected) return location.reload();
			if (!response.ok) return;
			fresh = new DOMParser().parseFromString(await response.text(), "text/html");
		} catch {
			return; // offline for a moment, the next round tries again
		}
		const now = document.getElementById("stats-page");
		const next = fresh.getElementById("stats-page");
		if (now && next) {
			now.replaceWith(next);
			prepare();
		}
	}

	prepare();
	setInterval(refresh, 60 * 1000);
})();
