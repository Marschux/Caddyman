// A copy button in the corner of every box with a command or a value, so nobody has to
// select it by hand. The two versions of a conflict are for reading, not for copying.
for (const pre of document.querySelectorAll("pre:not(.conflict pre)")) {
	const box = document.createElement("div");
	box.className = "copyable";
	pre.replaceWith(box);
	const button = document.createElement("button");
	button.type = "button";
	button.className = "secondary";
	button.textContent = "Copy";
	button.addEventListener("click", async () => {
		try {
			await navigator.clipboard.writeText(pre.textContent);
		} catch {
			// Plain http has no clipboard API: select the text and copy the old way.
			getSelection().selectAllChildren(pre);
			document.execCommand("copy");
			getSelection().removeAllRanges();
		}
		button.textContent = "Copied";
		setTimeout(() => { button.textContent = "Copy"; }, 2000);
	});
	box.append(pre, button);
}
