// "Cert Runner" - a hidden game. Type the name into the search of the route list and press Enter
// five times: the one it is named after only comes when he is called five times.
(() => {
	const search = document.querySelector('#route-filter input[name="q"]');
	if (!search) return;

	const NAME = "candyman";
	const CALLS = 5;
	const BEST = "caddyman-runner-best";
	// The field in its own units; the canvas is scaled to the window by CSS.
	const WIDTH = 800, HEIGHT = 240, GROUND = 200;
	const GRAVITY = 2600, JUMP = 780, SHORT_HOP = 300;
	// The second jump, in the air, is a little weaker. Holding down in the air pulls to the ground.
	const AIR_JUMP = 660, AIR_JUMPS = 1, DIVE = 3600;
	const START_SPEED = 320, TOP_SPEED = 860, FASTER = 9;
	// A little room on every side, so a touch that only looks like one does not count.
	const MERCY = 5;
	const PLAYER = { x: 70, width: 26, height: 30, ducked: 16 };
	// What stands in the way: the label, how wide, how high, how far above the ground, what it says
	// when it is hit, and the stage it first shows up in. What hangs in the air is ducked under.
	const OBSTACLES = [
		["502", 34, 26, 0, "502 Bad Gateway", 0],
		["504", 34, 26, 0, "504 Gateway Timeout", 0],
		["EXPIRED", 66, 22, 0, "Certificate expired", 0],
		["DDoS", 44, 22, 20, "Knocked over by a DDoS", 1],
		["CVE", 32, 44, 0, "Unpatched CVE", 1],
		["TIMEOUT", 68, 34, 0, "The upstream timed out", 2],
		["MITM", 44, 26, 22, "A man in the middle", 3],
	];
	// A new stage every so many points. The last one goes on for ever.
	const STAGES = ["HTTP", "TLS 1.0", "TLS 1.2", "TLS 1.3", "HSTS", "mTLS", "Post-quantum"];
	const STAGE_POINTS = 500;
	// Certificates to pick up: points for each, and every fifth is a shield that takes one hit.
	const CERT = { width: 40, tall: 18, lifts: [6, 60, 95], points: 50, shield: 5 };
	const UP = [" ", "ArrowUp", "w"], DOWN = ["ArrowDown", "s"];

	// How often Enter was pressed on the name. Typing anything starts the count again.
	let called = 0;
	search.addEventListener("input", () => { called = 0; });
	search.addEventListener("keydown", (event) => {
		if (event.key !== "Enter" || search.value.trim().toLowerCase() !== NAME) return;
		event.preventDefault();
		called += 1;
		if (called < CALLS) return;
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
	const box = (thing) => [thing.x, GROUND - thing.lift - thing.tall, thing.width, thing.tall];

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
		const screen = element("div", "game");
		screen.setAttribute("role", "dialog");
		screen.setAttribute("aria-label", "Cert Runner");
		const score = element("p", "game-score");
		const top = element("p", "game-best");
		const close = element("button", "link", "Close");
		close.type = "button";
		const header = element("header", "");
		header.append(element("strong", "", "Cert Runner"), close);
		const canvas = element("canvas", "game-canvas");
		canvas.width = WIDTH;
		canvas.height = HEIGHT;
		const say = element("p", "game-say");
		const field = element("div", "game-field");
		// The score stands in the middle, above the field, where the eyes are anyway.
		field.append(score, top, canvas, say);
		const help = "Space, arrow up or a click: jump, and once more in the air. Hold for a higher jump. Arrow down: duck. Esc: close.";
		screen.append(header, field, element("p", "game-help", help));
		document.body.append(screen);

		const pen = canvas.getContext("2d");
		// The colours of the look that is switched on.
		const style = getComputedStyle(document.documentElement);
		const colour = (name) => style.getPropertyValue(name).trim();
		const LINE = colour("--hairline-strong"), MUTED = colour("--ink-muted");
		const PRODUCT = colour("--product"), ERROR = colour("--error"), OK = colour("--ok");
		const MONO = `600 11px ${colour("--mono") || "monospace"}`;

		let frame = 0, last = 0, over = false, held = false, low = false;
		let speed, distance, height, rise, jumps, obstacles, gap, certs, certGap, record;
		let bonus, collected, shield, stage, sayUntil;

		function reset() {
			speed = START_SPEED;
			distance = 0;
			height = 0; // above the ground
			rise = 0; // upwards is positive
			jumps = 0; // made in the air since the last landing
			obstacles = [];
			gap = 500;
			certs = [];
			certGap = 900;
			bonus = 0;
			collected = 0;
			shield = false;
			stage = 0;
			sayUntil = 0;
			over = false;
			record = best(0);
			say.textContent = "";
			last = 0;
			cancelAnimationFrame(frame);
			frame = requestAnimationFrame(step);
		}

		// A line below the field that goes away by itself.
		function tell(text, now) {
			say.textContent = text;
			sayUntil = now + 1600;
		}

		function jump() {
			if (over) return reset();
			held = true;
			if (height === 0) {
				rise = JUMP;
			} else if (jumps < AIR_JUMPS) {
				jumps += 1;
				rise = AIR_JUMP;
			}
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
			rise -= (GRAVITY + (low && height > 0 ? DIVE : 0)) * passed;
			height = Math.max(0, height + rise * passed);
			if (height === 0) {
				jumps = 0;
				rise = held && !low ? JUMP : 0;
			}

			const reached = Math.min(STAGES.length - 1, Math.floor(distance / 10 / STAGE_POINTS));
			if (reached > stage) {
				stage = reached;
				tell(`Stage ${stage + 1}: ${STAGES[stage]}`, now);
			}

			gap -= speed * passed;
			if (gap <= 0) {
				const known = OBSTACLES.filter((obstacle) => obstacle[5] <= stage);
				const [label, width, tall, lift, end] = known[Math.floor(Math.random() * known.length)];
				obstacles.push({ label, width, tall, lift, end, x: WIDTH });
				// Far enough apart to land and jump again, closer together the longer it goes.
				gap = width + speed * (0.75 + Math.random() * 0.9);
			}
			certGap -= speed * passed;
			if (certGap <= 0) {
				const lift = CERT.lifts[Math.floor(Math.random() * CERT.lifts.length)];
				certs.push({ width: CERT.width, tall: CERT.tall, lift, x: WIDTH });
				certGap = 700 + Math.random() * 1100;
			}
			for (const thing of [...obstacles, ...certs]) thing.x -= speed * passed;
			obstacles = obstacles.filter((obstacle) => obstacle.x + obstacle.width > 0);
			certs = certs.filter((cert) => cert.x + cert.width > 0);

			const tall = low ? PLAYER.ducked : PLAYER.height;
			const me = [PLAYER.x + MERCY, GROUND - height - tall + MERCY, PLAYER.width - 2 * MERCY, tall - MERCY];
			// For a certificate the whole body counts: picking one up should be easy.
			const body = [PLAYER.x, GROUND - height - tall, PLAYER.width, tall];
			const taken = certs.find((cert) => overlap(body, box(cert)));
			if (taken) {
				certs = certs.filter((cert) => cert !== taken);
				bonus += CERT.points;
				collected += 1;
				if (collected % CERT.shield === 0 && !shield) {
					shield = true;
					tell("Shield up: the next hit does not count", now);
				}
			}
			let hit = obstacles.find((obstacle) => overlap(me, box(obstacle)));
			if (hit && shield) {
				shield = false;
				obstacles = obstacles.filter((obstacle) => obstacle !== hit);
				tell(`${hit.end}: the shield took it`, now);
				hit = null;
			}
			if (sayUntil && now > sayUntil) {
				say.textContent = "";
				sayUntil = 0;
			}
			draw();
			const points = Math.floor(distance / 10) + bonus;
			const line = `Certificates ${collected} - best`;
			score.textContent = points;
			if (!hit) {
				top.textContent = `${line} ${Math.max(record, points)}`;
				frame = requestAnimationFrame(step);
				return;
			}
			over = true;
			top.textContent = `${line} ${best(points)}`;
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

			pen.font = MONO;
			pen.textBaseline = "middle";
			pen.textAlign = "left";
			pen.fillStyle = MUTED;
			pen.fillText(`Stage ${stage + 1}: ${STAGES[stage]}`, 8, 14);

			// The lock from the logo: a body with a shackle. Ducked, the shackle is pushed in.
			const tall = low ? PLAYER.ducked : PLAYER.height;
			const head = GROUND - height - tall;
			const shackle = low ? 4 : 12;
			pen.strokeStyle = PRODUCT;
			pen.lineWidth = 4;
			pen.beginPath();
			pen.arc(PLAYER.x + PLAYER.width / 2, head + shackle, 7, Math.PI, 0);
			pen.stroke();
			pen.fillStyle = PRODUCT;
			pen.beginPath();
			pen.roundRect(PLAYER.x, head + shackle, PLAYER.width, tall - shackle, 4);
			pen.fill();
			if (shield) {
				pen.strokeStyle = OK;
				pen.lineWidth = 2;
				pen.beginPath();
				pen.arc(PLAYER.x + PLAYER.width / 2, GROUND - height - tall / 2, 26, 0, 2 * Math.PI);
				pen.stroke();
			}

			pen.textAlign = "center";
			pen.lineWidth = 1.5;
			for (const [things, tint, name] of [[obstacles, ERROR, null], [certs, OK, "CERT"]]) {
				for (const thing of things) {
					const [x, y, width, high] = box(thing);
					pen.strokeStyle = tint;
					pen.beginPath();
					pen.roundRect(x + 0.5, y + 0.5, width - 1, high - 1, 4);
					pen.stroke();
					pen.fillStyle = tint;
					pen.fillText(name || thing.label, x + width / 2, y + high / 2 + 1);
				}
			}
		}

		function down(event) {
			if (event.key === "Escape") return stop();
			if (DOWN.includes(event.key)) {
				event.preventDefault();
				low = true;
				return;
			}
			if (!UP.includes(event.key)) return;
			event.preventDefault();
			if (!event.repeat) jump();
		}

		function up(event) {
			if (DOWN.includes(event.key)) low = false;
			if (UP.includes(event.key)) release();
		}

		function stop() {
			cancelAnimationFrame(frame);
			document.removeEventListener("keydown", down);
			document.removeEventListener("keyup", up);
			screen.remove();
			search.focus();
		}

		close.addEventListener("click", stop);
		field.addEventListener("pointerdown", jump);
		field.addEventListener("pointerup", release);
		document.addEventListener("keydown", down);
		document.addEventListener("keyup", up);
		// Not on a button: Space would press it.
		screen.tabIndex = -1;
		screen.focus();
		reset();
	}
})();
