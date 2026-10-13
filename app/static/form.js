// The lists of fields in the route form: a button adds an entry, the x next to an entry removes it.
// Without this script the fields that are there still work: an emptied one is dropped on saving.
document.addEventListener("click", (event) => {
	const remove = event.target.closest(".entry .remove");
	if (remove) {
		remove.parentElement.remove();
		return;
	}
	const add = event.target.closest("[data-add]");
	if (!add) return;
	// One [name, hint] per field of the entry: one for a hostname or a network, two for a path and its target.
	const fields = JSON.parse(add.dataset.add);
	const entry = document.createElement("span");
	entry.className = fields.length > 1 ? "entry pair" : "entry";
	for (const [name, hint] of fields) {
		const field = document.createElement("input");
		field.name = name;
		field.autocomplete = "off";
		field.placeholder = hint;
		field.setAttribute("aria-label", hint);
		entry.append(field);
	}
	const button = document.createElement("button");
	button.type = "button";
	button.className = "remove";
	button.title = "Remove";
	button.setAttribute("aria-label", "Remove");
	button.textContent = "×";
	entry.append(button);
	add.closest("details").querySelector(".fields").append(entry);
	entry.querySelector("input").focus();
});
