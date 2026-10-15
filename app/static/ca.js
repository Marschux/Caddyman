// Picking another certificate swaps the page in place instead of loading it anew, so nothing flashes.
// Without this script the button under <noscript> loads the page the plain way.
document.addEventListener("change", async (event) => {
	const select = event.target.closest('select[name="cert"]');
	if (!select) return;
	const address = "?" + new URLSearchParams(new FormData(select.form));
	try {
		const response = await fetch(address, { headers: { Accept: "text/html" } });
		// A redirect means the session ended: let the browser show the login.
		if (!response.ok || response.redirected) throw new Error();
		const fresh = new DOMParser().parseFromString(await response.text(), "text/html");
		const main = fresh.querySelector("main");
		document.querySelector("main").replaceWith(main);
		addCopyButtons(main);
		history.replaceState(null, "", address);
	} catch {
		select.form.submit();
	}
});
