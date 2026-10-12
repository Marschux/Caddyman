// "You are the proxy" - a hidden game. Say the name five times in the route form.
(() => {
	const form = document.querySelector("form.route");
	if (!form) return;

	const NAME = "candyman";
	const LINES = [
		"The hostname 'candyman' is reserved.",
		"The hostname 'candyman' is still reserved.",
		"Please stop typing that name.",
		"That was four. You know how this ends.",
	];
	// Used when there are not enough real routes to fill three backends.
	const INVENTED = [
		["pdf.home.example", "10.0.0.12:9005"],
		["wiki.home.example", "10.0.0.14:3000"],
		["git.home.example", "10.0.0.20:3000"],
		["notes.home.example", "10.0.0.14:3000"],
		["scan.home.example", "10.0.0.12:9005"],
	];
	const MAX_ERRORS = 3;
	const KEYS = { ArrowLeft: 0, ArrowDown: 1, ArrowUp: 1, ArrowRight: 2, " ": -1 };

	let said = 0;
	const note = document.createElement("p");
	note.className = "error";
	note.setAttribute("role", "alert");

	form.addEventListener("submit", (event) => {
		if (form.elements.host.value.trim().toLowerCase() !== NAME) return;
		event.preventDefault();
		said += 1;
		if (said <= LINES.length) {
			note.textContent = LINES[said - 1];
			form.querySelector(".heading").after(note);
			return;
		}
		said = 0;
		note.remove();
		play();
	});

	const element = (tag, className, text = "") => {
		const node = document.createElement(tag);
		node.className = className;
		node.textContent = text;
		return node;
	};

	function play() {
		const pairs = [...JSON.parse(form.dataset.game || "[]"), ...INVENTED];
		const backends = [...new Set(pairs.map((pair) => pair[1]))].slice(0, 3);
		const hosts = pairs.filter((pair) => backends.includes(pair[1]));

		const box = element("div", "game");
		box.setAttribute("role", "dialog");
		box.setAttribute("aria-label", "You are the proxy");
		const score = element("span", "game-score");
		const close = element("button", "link", "Close");
		close.type = "button";
		const header = element("header", "");
		header.append(element("strong", "", "You are the proxy"), score, close);
		const request = element("div", "game-request");
		const say = element("p", "game-say");
		const field = element("div", "game-field");
		field.append(request, say);
		const lanes = element("div", "game-backends");
		backends.forEach((backend, lane) => {
			const button = element("button", "", backend);
			button.type = "button";
			const names = hosts.filter((pair) => pair[1] === backend).map((pair) => pair[0]);
			button.append(element("small", "", [...new Set(names)].join(", ")));
			button.addEventListener("click", () => answer(lane));
			lanes.append(button);
		});
		const help = "Arrow keys or click: forward to a backend. Space: reject an expired certificate. Esc: close.";
		box.append(header, field, lanes, element("p", "game-help", help));
		document.body.append(box);

		let points = 0;
		let errors = 0;
		let current = null;
		let timer = 0;

		const board = () => {
			score.textContent = `Score ${points} - errors ${errors}/${MAX_ERRORS}`;
		};

		function next() {
			const pick = hosts[Math.floor(Math.random() * hosts.length)];
			// Expired certificates only show up once the basics are learned.
			const expired = points >= 5 && Math.random() < 0.25;
			current = { backend: backends.indexOf(pick[1]), expired };
			request.textContent = pick[0] + (expired ? " - certificate expired" : "");
			request.classList.toggle("expired", expired);
			request.hidden = false;
			request.style.transition = "none";
			request.style.top = "0";
			void request.offsetHeight; // apply the reset before the fall starts
			const fall = Math.max(1200, 4000 - points * 150);
			request.style.transition = `top ${fall}ms linear`;
			request.style.top = "100%";
			// The transition is only what it looks like; the clock decides when it is missed.
			timer = setTimeout(() => answer(null), fall);
		}

		// lane: 0 to 2 forwards, -1 rejects, null means the request fell through.
		function answer(lane) {
			if (!current) return;
			const { backend, expired } = current;
			current = null;
			clearTimeout(timer);
			let problem = "";
			if (lane === null) problem = "504 Gateway Timeout";
			else if (expired) problem = lane === -1 ? "" : "You served an expired certificate";
			else if (lane === -1) problem = "503 - that request was fine";
			else if (lane !== backend) problem = "502 Bad Gateway";
			if (problem) errors += 1;
			else points += 1;
			say.textContent = problem || (expired ? "Rejected" : "200 OK");
			say.classList.toggle("bad", Boolean(problem));
			request.hidden = true;
			board();
			if (errors < MAX_ERRORS) return void setTimeout(next, 500);
			say.textContent = `${problem}. Three errors, the upstream is yours no more. Final score: ${points}`;
			const again = element("button", "", "Play again");
			again.type = "button";
			again.addEventListener("click", () => {
				again.remove();
				points = errors = 0;
				say.textContent = "";
				board();
				next();
			});
			field.append(again);
			again.focus();
		}

		function keys(event) {
			if (event.key === "Escape") return stop();
			if (!(event.key in KEYS) || !current) return;
			event.preventDefault();
			answer(KEYS[event.key]);
		}

		function stop() {
			clearTimeout(timer);
			current = null;
			document.removeEventListener("keydown", keys);
			box.remove();
		}

		close.addEventListener("click", stop);
		document.addEventListener("keydown", keys);
		// Not on a button: Space would press it between two requests.
		box.tabIndex = -1;
		box.focus();
		board();
		next();
	}
})();
