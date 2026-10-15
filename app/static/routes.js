// Search, "only problems", "no groups" and sorting for the list of routes. Everything works on the
// rows the server sent; the rows of a group stay below its name unless "no groups" is ticked.
(() => {
	const filter = document.getElementById("route-filter");
	if (!filter) return;
	const table = document.querySelector("table");
	const body = table.tBodies[0];
	// As the server sent them: the name of a group, then its routes.
	const initial = [...body.rows];
	const routes = initial.filter((row) => !row.classList.contains("group"));
	const groups = initial.filter((row) => row.classList.contains("group"));
	// What the search looks at: every cell but the buttons, plus the name of the group.
	const text = new Map(routes.map((row) => [row, cells(row).join(" ").toLowerCase() + " " + (row.dataset.group || "").toLowerCase()]));
	const none = body.insertRow();
	none.innerHTML = '<td colspan="7" class="empty">No route matches.</td>';
	// The column picked by a click on its title, and the direction. Nothing picked: the order of the server.
	let sorting = null;

	function cells(row) {
		return [...row.cells].slice(0, -1).map((cell) => cell.textContent.replace(/\s+/g, " ").trim());
	}

	// The box is only there when the list has groups.
	function flat() {
		return Boolean(filter.elements.flat && filter.elements.flat.checked);
	}

	function apply() {
		const query = filter.elements.q.value.trim().toLowerCase();
		const problems = filter.elements.problems.checked;
		const grouped = !flat();
		let shown = 0;
		let group = null;
		for (const row of [...body.rows]) {
			if (row === none) continue;
			if (row.classList.contains("group")) {
				// Stays hidden until one of its routes shows, and all the time in the list without groups.
				group = grouped ? row : null;
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

	function arrange() {
		const [column, descending] = sorting || [0, false];
		// A hand-written file fills the first two columns and the TLS column; it sorts as empty in the others.
		const key = (row) => {
			if (row.cells.length === 7 || column <= 1) return cells(row)[column];
			return column === 5 ? cells(row)[2] : "";
		};
		const sorted = (rows) => rows.sort((a, b) => key(a).localeCompare(key(b), undefined, { numeric: true }) * (descending ? -1 : 1));
		if (flat()) {
			// One list, by host unless a column was picked. The names of the groups wait hidden at its end.
			body.append(...sorted([...routes]), ...groups, none);
			return;
		}
		if (!sorting) {
			body.append(...initial, none);
			return;
		}
		let run = [];
		const order = [];
		for (const row of initial) {
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
			sorting = [column, descending];
			arrange();
			apply();
		});
	});

	// "No groups" is kept in this browser, so the list opens the way it was left. Without storage
	// (private window, blocked site data) it just starts with groups.
	const KEPT = "caddyman.routes.flat";
	const store = (action) => {
		try {
			return action(localStorage);
		} catch (error) {
			return null;
		}
	};

	filter.addEventListener("input", apply);
	// The box sits in the last column title, outside the form it belongs to, so it is asked itself.
	const box = filter.elements.flat;
	if (box) {
		box.addEventListener("input", () => {
			store((kept) => (box.checked ? kept.setItem(KEPT, "1") : kept.removeItem(KEPT)));
			arrange();
			apply();
		});
		if (store((kept) => kept.getItem(KEPT)) === "1") {
			box.checked = true;
			arrange();
		}
		box.closest("label").hidden = false;
	}
	// Sits there too, so its input does not reach the form either.
	const problems = filter.elements.problems;
	problems.addEventListener("input", apply);
	problems.closest("label").hidden = false;
	filter.hidden = false;
	apply();
})();
