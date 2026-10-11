// Search, "only problems" and sorting for the list of routes. Everything works on the rows
// the server sent; the rows of a group stay below its name.
(() => {
	const filter = document.getElementById("route-filter");
	if (!filter) return;
	const table = document.querySelector("table");
	const body = table.tBodies[0];
	const routes = [...body.rows].filter((row) => !row.classList.contains("group"));
	// What the search looks at: every cell but the buttons, plus the name of the group.
	const text = new Map(routes.map((row) => [row, cells(row).join(" ").toLowerCase() + " " + (row.dataset.group || "").toLowerCase()]));
	const none = body.insertRow();
	none.innerHTML = '<td colspan="6" class="empty">No route matches.</td>';

	function cells(row) {
		return [...row.cells].slice(0, -1).map((cell) => cell.textContent.replace(/\s+/g, " ").trim());
	}

	function apply() {
		const query = filter.elements.q.value.trim().toLowerCase();
		const problems = filter.elements.problems.checked;
		let shown = 0;
		let group = null;
		for (const row of [...body.rows]) {
			if (row === none) continue;
			if (row.classList.contains("group")) {
				// Stays hidden until one of its routes shows.
				group = row;
				row.hidden = true;
				continue;
			}
			row.hidden = !text.get(row).includes(query) || (problems && !("problem" in row.dataset));
			if (row.hidden) continue;
			shown += 1;
			if (group) group.hidden = false;
		}
		none.hidden = shown > 0;
	}

	function sort(column, descending) {
		// A hand-written file fills the first column and the certificate; it sorts as empty in the others.
		const key = (row) => {
			if (row.cells.length === 6 || column === 0) return cells(row)[column];
			return column === 4 ? cells(row)[2] : "";
		};
		const sorted = (rows) => rows.sort((a, b) => key(a).localeCompare(key(b), undefined, { numeric: true }) * (descending ? -1 : 1));
		let run = [];
		const order = [];
		for (const row of [...body.rows]) {
			if (row === none) continue;
			if (row.classList.contains("group")) {
				order.push(...sorted(run), row);
				run = [];
			} else {
				run.push(row);
			}
		}
		body.append(...order, ...sorted(run), none);
	}

	[...table.tHead.rows[0].cells].slice(0, -1).forEach((head, column) => {
		const button = document.createElement("button");
		button.type = "button";
		button.className = "sort";
		button.textContent = head.textContent;
		head.replaceChildren(button);
		button.addEventListener("click", () => {
			const descending = head.getAttribute("aria-sort") === "ascending";
			for (const other of table.tHead.rows[0].cells) other.removeAttribute("aria-sort");
			head.setAttribute("aria-sort", descending ? "descending" : "ascending");
			sort(column, descending);
		});
	});

	filter.addEventListener("input", apply);
	filter.hidden = false;
	apply();
})();
