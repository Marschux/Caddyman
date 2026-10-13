// "Cert Runner" - a hidden game. Type the name into the search of the route list and press Enter.
(() => {
	const search = document.querySelector('#route-filter input[name="q"]');
	if (!search) return;

	const NAME = "candyman";
	const BEST = "caddyman-runner-best";
	// The field in its own units; the canvas is scaled to the window by CSS.
	const WIDTH = 800, HEIGHT = 240, GROUND = 200;
	const GRAVITY = 2600, JUMP = 780, SHORT_HOP = 300;
	const START_SPEED = 320, TOP_SPEED = 860, FASTER = 9;
	// A little room on every side, so a touch that only looks like one does not count.
	const MERCY = 5;
	const PLAYER = { x: 70, width: 26, height: 30 };
	// What stands in the way: the label, how wide, how high, and what it says when it is hit.
	const OBSTACLES = [
		["502", 34, 26, "502 Bad Gateway"],
		["504", 34, 26, "504 Gateway Timeout"],
		["CVE", 32, 44, "Unpatched CVE"],
		["EXPIRED", 66, 22, "Certificate expired"],
		["TIMEOUT", 68, 34, "The upstream timed out"],
	];
	const KEYS = [" ", "ArrowUp", "w"];

	search.addEventListener("keydown", (event) => {
		if (event.key !== "Enter" || search.value.trim().toLowerCase() !== NAME) return;
		event.preventDefault();
		search.value = "";
		search.dispatchEvent(new Event("input", { bubbles: true }));
		play();
	});

	const element = (tag, className, text = "") => {
		const node = document.createElement(tag);
		node.className = className;
		node.textContent = text;
		return node;
	};

	// Two boxes given as [x, y, width, height].
	const overlap = (a, b) => a[0] < b[0] + b[2] && a[0] + a[2] > b[0] && a[1] < b[1] + b[3] && a[1] + a[3] > b[1];

	function best(points) {
		// A browser may refuse to store anything; the game is the same without a record.
		try {
			const stored = Number(localStorage.getItem(BEST)) || 0;
			if (points > stored) localStorage.setItem(BEST, String(points));
			return Math.max(stored, points || 0);
		} catch {
			return points || 0;
		}
	}

	function play() {
		const box = element("div", "game");
		box.setAttribute("role", "dialog");
		box.setAttribute("aria-label", "Cert Runner");
		const score = element("span", "game-score");
		const close = element("button", "link", "Close");
		close.type = "button";
		const header = element("header", "");
		header.append(element("strong", "", "Cert Runner"), score, close);
		const canvas = element("canvas", "game-canvas");
		canvas.width = WIDTH;
		canvas.height = HEIGHT;
		const say = element("p", "game-say");
		const field = element("div", "game-field");
		field.append(canvas, say);
		box.append(header, field, element("p", "game-help", "Space, arrow up or a click: jump. Hold for a higher jump. Esc: close."));
		document.body.append(box);

		const pen = canvas.getContext("2d");
		// The colours of the look that is switched on.
		const style = getComputedStyle(document.documentElement);
		const colour = (name) => style.getPropertyValue(name).trim();
		const LINE = colour("--hairline-strong");
		const PRODUCT = colour("--product"), ERROR = colour("--error");
		const MONO = `600 11px ${colour("--mono") || "monospace"}`;

		let frame = 0, last = 0, over = false, held = false;
		let speed, distance, height, rise, obstacles, gap, record;

		function reset() {
			speed = START_SPEED;
			distance = 0;
			height = 0; // above the ground
			rise = 0; // upwards is positive
			obstacles = [];
			gap = 500;
			over = false;
			record = best(0);
			say.textContent = "";
			last = 0;
			cancelAnimationFrame(frame);
			frame = requestAnimationFrame(step);
		}

		function jump() {
			if (over) return reset();
			held = true;
			if (height === 0) rise = JUMP;
		}

		function release() {
			held = false;
			// Letting go early cuts the jump short.
			if (rise > SHORT_HOP) rise = SHORT_HOP;
		}

		function step(now) {
			// A tab in the background hands in one huge step: never more than a twentieth of a second.
			const passed = Math.min((now - (last || now)) / 1000, 0.05);
			last = now;
			speed = Math.min(TOP_SPEED, speed + FASTER * passed);
			distance += speed * passed;
			rise -= GRAVITY * passed;
			height = Math.max(0, height + rise * passed);
			if (height === 0) rise = held ? JUMP : 0;

			gap -= speed * passed;
			if (gap <= 0) {
				const [label, width, tall, end] = OBSTACLES[Math.floor(Math.random() * OBSTACLES.length)];
				obstacles.push({ label, width, tall, end, x: WIDTH });
				// Far enough apart to land and jump again, closer together the longer it goes.
				gap = width + speed * (0.75 + Math.random() * 0.9);
			}
			for (const obstacle of obstacles) obstacle.x -= speed * passed;
			obstacles = obstacles.filter((obstacle) => obstacle.x + obstacle.width > 0);

			const me = [PLAYER.x + MERCY, GROUND - height - PLAYER.height + MERCY, PLAYER.width - 2 * MERCY, PLAYER.height - MERCY];
			const hit = obstacles.find((obstacle) => overlap(me, [obstacle.x, GROUND - obstacle.tall, obstacle.width, obstacle.tall]));
			draw();
			const points = Math.floor(distance / 10);
			if (!hit) {
				score.textContent = `Score ${points} - best ${Math.max(record, points)}`;
				frame = requestAnimationFrame(step);
				return;
			}
			over = true;
			score.textContent = `Score ${points} - best ${best(points)}`;
			say.textContent = `${hit.end}. Space to run again.`;
		}

		function draw() {
			pen.clearRect(0, 0, WIDTH, HEIGHT);
			pen.strokeStyle = LINE;
			pen.lineWidth = 1;
			pen.beginPath();
			pen.moveTo(0, GROUND + 0.5);
			pen.lineTo(WIDTH, GROUND + 0.5);
			pen.stroke();
			// Marks on the ground, so the speed shows.
			pen.fillStyle = LINE;
			for (let x = -(distance % 80); x < WIDTH; x += 80) pen.fillRect(x, GROUND + 8, 14, 2);

			// The lock from the logo: a body with a shackle.
			const top = GROUND - height - PLAYER.height;
			pen.strokeStyle = PRODUCT;
			pen.lineWidth = 4;
			pen.beginPath();
			pen.arc(PLAYER.x + PLAYER.width / 2, top + 12, 7, Math.PI, 0);
			pen.stroke();
			pen.fillStyle = PRODUCT;
			pen.beginPath();
			pen.roundRect(PLAYER.x, top + 12, PLAYER.width, PLAYER.height - 12, 4);
			pen.fill();

			pen.font = MONO;
			pen.textAlign = "center";
			pen.textBaseline = "middle";
			pen.lineWidth = 1.5;
			for (const obstacle of obstacles) {
				const y = GROUND - obstacle.tall;
				pen.strokeStyle = ERROR;
				pen.beginPath();
				pen.roundRect(obstacle.x + 0.5, y + 0.5, obstacle.width - 1, obstacle.tall - 1, 4);
				pen.stroke();
				pen.fillStyle = ERROR;
				pen.fillText(obstacle.label, obstacle.x + obstacle.width / 2, y + obstacle.tall / 2 + 1);
			}
		}

		function down(event) {
			if (event.key === "Escape") return stop();
			if (!KEYS.includes(event.key)) return;
			event.preventDefault();
			if (!event.repeat) jump();
		}

		function up(event) {
			if (KEYS.includes(event.key)) release();
		}

		function stop() {
			cancelAnimationFrame(frame);
			document.removeEventListener("keydown", down);
			document.removeEventListener("keyup", up);
			box.remove();
			search.focus();
		}

		close.addEventListener("click", stop);
		field.addEventListener("pointerdown", jump);
		field.addEventListener("pointerup", release);
		document.addEventListener("keydown", down);
		document.addEventListener("keyup", up);
		// Not on a button: Space would press it.
		box.tabIndex = -1;
		box.focus();
		reset();
	}
})();
