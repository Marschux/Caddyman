// A form with data-confirm asks that question before it is sent. Here instead of an onsubmit in
// the page, so the pages carry no script of their own.
document.addEventListener("submit", (event) => {
	const question = event.target.dataset.confirm;
	if (question && !confirm(question)) event.preventDefault();
});
