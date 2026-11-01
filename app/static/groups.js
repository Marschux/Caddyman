// Drag a group by its handle to a new place; the new order is sent at once and the page comes back.
const body = document.querySelector("table.groups tbody");
const names = () => [...body.querySelectorAll("tr[data-name]")].map((row) => row.dataset.name);
let dragged = null;
let before = "";
body.addEventListener("dragstart", (event) => {
	dragged = event.target.closest(".grip") && event.target.closest("tr");
	if (!dragged) return;
	before = names().join("\n");
	event.dataTransfer.effectAllowed = "move";
	event.dataTransfer.setDragImage(dragged, 0, 0);
	dragged.classList.add("dragged");
});
body.addEventListener("dragover", (event) => {
	const row = event.target.closest("tr[data-name]");
	if (!dragged || !row) return;
	event.preventDefault();
	if (row === dragged) return;
	const below = event.clientY > row.getBoundingClientRect().top + row.offsetHeight / 2;
	if (below) row.after(dragged);
	else row.before(dragged);
});
body.addEventListener("dragend", () => {
	if (!dragged) return;
	dragged.classList.remove("dragged");
	dragged = null;
	if (names().join("\n") === before) return;
	const form = document.getElementById("group-order");
	for (const name of names()) {
		const input = document.createElement("input");
		input.type = "hidden";
		input.name = "name";
		input.value = name;
		form.append(input);
	}
	form.submit();
});
