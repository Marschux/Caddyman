// Search, "problems", "to do", "no groups", sorting and pages for the list of routes. Everything works on the
// rows the server sent; the rows of a group stay below its name unless "no groups" is ticked.
(() => {
	const filter = document.getElementById("route-filter");
	if (!filter) return;
	// Filtering happens as you type; Enter sends nothing.
	filter.addEventListener("submit", (event) => event.preventDefault());
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
	// The page shown and how many there are; a new search or filter starts at the first.
	let page = 1;
	let pages = 1;
	const pager = document.getElementById("route-pager");
	pager.addEventListener("click", (event) => {
		const { step, page: picked } = event.target.dataset;
		if (!step && !picked) return;
		page = picked ? Number(picked) : page + Number(step);
		apply();
		table.scrollIntoView({ block: "start" });
	});

	function cells(row) {
		return [...row.cells].slice(0, -1).map((cell) => cell.textContent.replace(/\s+/g, " ").trim());
	}

	// The box is only there when the list has groups.
	function flat() {
		return Boolean(filter.elements.flat && filter.elements.flat.checked);
	}

	function apply() {
		const query = filter.elements.q.value.trim().toLowerCase();
		// Both ticked: a row shows if it is either.
		const wanted = [filter.elements.problems.checked && "problem", filter.elements.todo.checked && "todo"].filter(Boolean);
		const grouped = !flat();
		let shown = 0;
		let group = null;
		let count = 0;
		// What takes a place on a page: a matching route with the name of its group, or a folded group.
		const lines = [];
		const close = () => group && (group.querySelector(".count").textContent = count);
		for (const row of [...body.rows]) {
			if (row === none) continue;
			// Everything starts hidden; the page shows its own lines below.
			row.hidden = true;
			if (row.classList.contains("group")) {
				close();
				// Stays hidden until one of its routes shows, and all the time in the list without groups.
				group = grouped ? row : null;
				count = 0;
				row.querySelector("button").setAttribute("aria-expanded", String(!collapsed.has(row.dataset.group)));
				continue;
			}
			const match = text.get(row).includes(query) && (!wanted.length || wanted.some((key) => key in row.dataset));
			if (!match) continue;
			shown += 1;
			count += 1;
			// A folded group still shows its name and how many of its routes match, on one line.
			if (group && collapsed.has(group.dataset.group)) {
				if (count === 1) lines.push([group]);
			} else {
				lines.push([row, group]);
			}
		}
		close();
		const size = Number(filter.elements.per.value) || lines.length || 1;
		pages = Math.max(1, Math.ceil(lines.length / size));
		page = Math.min(page, pages);
		for (const line of lines.slice((page - 1) * size, page * size)) {
			for (const row of line) if (row) row.hidden = false;
		}
		pager.hidden = pages === 1;
		pager.querySelector("small").textContent = `Page ${page} of ${pages}`;
		pager.querySelector('[data-step="-1"]').hidden = page === 1;
		pager.querySelector('[data-step="1"]').hidden = page === pages;
		// The first, the last and two either side of this one; a gap stands for what is left out.
		const numbers = pager.querySelector(".pages");
		numbers.replaceChildren();
		let last = 0;
		for (let number = 1; number <= pages; number += 1) {
			if (number !== 1 && number !== pages && Math.abs(number - page) > 2) continue;
			if (number - last > 1) numbers.append(Object.assign(document.createElement("span"), { className: "gap", textContent: "…" }));
			const button = Object.assign(document.createElement("button"), { type: "button", className: "secondary", textContent: number });
			button.dataset.page = number;
			if (number === page) button.setAttribute("aria-current", "page");
			numbers.append(button);
			last = number;
		}
		none.hidden = shown > 0;
		total.textContent = shown;
		if (all) {
			all.hidden = !grouped;
			all.setAttribute("aria-expanded", String(groups.some((row) => !collapsed.has(row.dataset.group))));
		}
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

	// Folded groups are kept in this browser too, by name.
	const SHUT = "caddyman.routes.folded";
	// Anything but a list in the storage counts as nothing folded.
	const folded = store((kept) => JSON.parse(kept.getItem(SHUT) || "[]"));
	const collapsed = new Set(Array.isArray(folded) ? folded.map(String) : []);
	const keep = () => store((kept) => kept.setItem(SHUT, JSON.stringify([...collapsed])));
	// Above the list: the number of routes shown, and one arrow that folds every group or opens them all again.
	const first = table.tHead.rows[0].cells[0];
	const total = document.createElement("span");
	total.className = "count";
	first.append(total);
	let all = null;
	if (groups.length) {
		all = document.createElement("button");
		all.type = "button";
		all.className = "fold";
		all.setAttribute("aria-label", "Fold or open all groups");
		first.prepend(all);
		all.addEventListener("click", () => {
			const open = groups.some((row) => !collapsed.has(row.dataset.group));
			for (const row of groups) open ? collapsed.add(row.dataset.group) : collapsed.delete(row.dataset.group);
			keep();
			apply();
		});
	}
	for (const row of groups) {
		const button = document.createElement("button");
		button.type = "button";
		button.className = "fold";
		button.textContent = row.cells[0].textContent;
		const count = document.createElement("span");
		count.className = "count";
		button.append(count);
		row.cells[0].replaceChildren(button);
		button.addEventListener("click", () => {
			const name = row.dataset.group;
			if (!collapsed.delete(name)) collapsed.add(name);
			keep();
			apply();
		});
	}

	// The number per page is kept in this browser as well.
	const PER = "caddyman.routes.per";
	const per = filter.elements.per;
	const kept = store((storage) => storage.getItem(PER));
	if ([...per.options].some((option) => option.value === kept)) per.value = kept;
	per.addEventListener("input", () => store((storage) => storage.setItem(PER, per.value)));
	const restart = () => {
		page = 1;
		apply();
	};
	filter.addEventListener("input", restart);
	// The box sits in the last column title, outside the form it belongs to, so it is asked itself.
	const box = filter.elements.flat;
	if (box) {
		box.addEventListener("input", () => {
			store((kept) => (box.checked ? kept.setItem(KEPT, "1") : kept.removeItem(KEPT)));
			arrange();
			restart();
		});
		if (store((kept) => kept.getItem(KEPT)) === "1") {
			box.checked = true;
			arrange();
		}
		box.closest("label").hidden = false;
	}
	// Sits there too, so its input does not reach the form either.
	for (const box of [filter.elements.problems, filter.elements.todo]) {
		box.addEventListener("input", restart);
		box.closest("label").hidden = false;
	}
	filter.hidden = false;
	apply();
})();
