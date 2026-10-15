// The lists of fields in the route form: a button adds an entry, the x next to an entry removes it.
// Without this script the fields that are there still work: an emptied one is dropped on saving.
document.addEventListener("click", (event) => {
	const remove = event.target.closest(".entry .remove");
	if (remove) {
		remove.parentElement.remove();
		syncVerify();
		return;
	}
	const add = event.target.closest("[data-add]");
	if (!add) return;
	// One [name, hint] per field of the entry: one for a hostname or a network, two for a path and its target.
	const fields = JSON.parse(add.dataset.add);
	const entry = document.createElement("span");
	entry.className = "entry";
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

// Not checking the target's certificate only means something for an https:// target;
// saving drops the option otherwise, so the box is not offered.
function syncVerify() {
	const box = document.querySelector("input[name=skip_verify]");
	if (!box) return;
	const targets = document.querySelectorAll("input[name=upstream], input[name=path_upstream]");
	const https = [...targets].some((field) => field.value.trim().startsWith("https://"));
	box.disabled = !https;
	if (!https) box.checked = false;
}
document.addEventListener("input", (event) => {
	if (event.target.matches("input[name=upstream], input[name=path_upstream]")) syncVerify();
});
syncVerify();
