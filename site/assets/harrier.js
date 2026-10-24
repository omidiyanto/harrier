// Harrier, the mascot: the 16 x 14 pixel bird from the logo, drawn as crisp
// SVG, with poses (sit, blink, wave, fly) and a few behaviours: the hero
// patrol over a field of agents, the bird that rides the docs reading
// progress, and small perched birds that wave. No dependencies.
(() => {
  "use strict";

  const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const COLORS = { "#": "#FF7A1A", d: "#C85A0E", k: "#1A0F08", y: "#FFD23F" };
  const BODY = [
    ".......######...",
    "......########..",
    ".....####kk###yy",
    ".....####kk###.y",
    "......########..",
    ".....#########..",
    "....##########..",
    "...###########..",
    "..############..",
    ".############...",
    "##..########....",
    "#....######.....",
    "......#..#......",
    ".....##.##......",
  ];
  // Rows replaced in each pose ("d" is the wing, a shade darker).
  const WING = { 6: "....##dddd####..", 7: "...##dddddd###..", 8: "..##ddddddd###..", 9: ".##ddddddd###...", 10: "##..#ddddd##...." };
  const UP = { 0: ".d.....######...", 1: ".dd...########..", 2: "..dd.####kk###yy", 3: "..ddd####kk###.y", 4: "...ddd########..", 5: "....dd########.." };
  const MID = { 5: ".dd..#########..", 6: ".ddddd########..", 7: "..dddd########.." };
  const DOWN = { 8: "..####dddd####..", 9: ".#####dddd###...", 10: "##..##ddddd#....", 11: "#....dddddd.....", 12: ".....dddd.......", 13: "......dd........" };
  const TUCK = { 12: "................", 13: "................" };
  const pose = (...overrides) => BODY.map((row, i) => overrides.reduce((r, o) => o[i] ?? r, row));
  const FRAMES = {
    sit: pose(WING),
    blink: pose(WING, { 2: ".....#########yy" }),
    waveUp: pose(UP),
    waveMid: pose(MID),
    fly1: pose(UP, TUCK),
    fly2: pose(MID, TUCK),
    fly3: pose(DOWN),
  };
  const FLIGHT = ["fly1", "fly2", "fly3", "fly2"];

  // One <rect> per horizontal run of one colour.
  function rects(rows) {
    let out = "";
    rows.forEach((line, y) => {
      for (let x = 0; x < line.length; ) {
        let n = 1;
        while (line[x + n] === line[x]) n++;
        if (line[x] !== ".") out += `<rect x="${x}" y="${y}" width="${n}" height="1" fill="${COLORS[line[x]]}"/>`;
        x += n;
      }
    });
    return out;
  }

  class Bird {
    constructor(host, scale, cls = "") {
      const el = document.createElement("span");
      el.className = `bird ${cls}`.trim();
      el.style.setProperty("--s", scale);
      el.innerHTML =
        `<span class="bird-bubble" aria-hidden="true"></span>` +
        `<svg viewBox="0 0 16 14" width="${16 * scale}" height="${14 * scale}" shape-rendering="crispEdges" aria-hidden="true">` +
        Object.entries(FRAMES).map(([name, rows]) => `<g data-pose="${name}">${rects(rows)}</g>`).join("") +
        `</svg>`;
      host.append(el);
      this.el = el;
      this.w = 16 * scale;
      this.h = 14 * scale;
      this.x = 0;
      this.y = 0;
      this.frames = Object.fromEntries([...el.querySelectorAll("g")].map((g) => [g.dataset.pose, g]));
      this.bubble = el.querySelector(".bird-bubble");
      this.timer = 0;
      this.idleTimer = 0;
      this.pose("sit");
    }
    pose(name) {
      for (const [n, g] of Object.entries(this.frames)) g.style.display = n === name ? "" : "none";
      this.current = name;
    }
    play(seq, fps) {
      this.stop();
      let i = 0;
      this.pose(seq[0]);
      this.timer = setInterval(() => this.pose(seq[++i % seq.length]), 1000 / fps);
    }
    stop() {
      clearInterval(this.timer);
      this.timer = 0;
    }
    sit() {
      this.stop();
      this.pose("sit");
    }
    flap() {
      this.idle(false);
      this.play(FLIGHT, 12);
    }
    face(dx) {
      this.el.style.setProperty("--flip", dx < 0 ? -1 : 1);
    }
    moveTo(x, y) {
      this.x = x;
      this.y = y;
      this.el.style.transform = `translate(${x.toFixed(1)}px, ${y.toFixed(1)}px)`;
    }
    wave(times = 3) {
      if (still) return Promise.resolve();
      this.idle(false);
      this.stop();
      return new Promise((done) => {
        let n = 0;
        this.pose("waveUp");
        this.timer = setInterval(() => {
          n += 1;
          if (n >= times * 2) {
            this.sit();
            done();
          } else this.pose(n % 2 ? "waveMid" : "waveUp");
        }, 130);
      });
    }
    say(text, ms = 2800) {
      this.bubble.textContent = text;
      this.bubble.classList.add("show");
      clearTimeout(this.sayTimer);
      this.sayTimer = setTimeout(() => this.bubble.classList.remove("show"), ms);
    }
    blink() {
      this.pose("blink");
      setTimeout(() => this.current === "blink" && this.pose("sit"), 140);
    }
    hop() {
      this.el.classList.remove("hop");
      void this.el.offsetWidth; // restart the animation
      this.el.classList.add("hop");
    }
    // Blink now and then, sometimes hop, while nothing else is playing.
    idle(on = true) {
      clearTimeout(this.idleTimer);
      if (!on || still) return;
      const tick = () => {
        if (!this.timer) Math.random() < 0.22 ? this.hop() : this.blink();
        this.idleTimer = setTimeout(tick, 1800 + Math.random() * 3400);
      };
      this.idleTimer = setTimeout(tick, 1400);
    }
  }

  const TIPS = [
    "One machine, one agent, one record.",
    "I check every agent every 5 minutes.",
    "No Wazuh credentials on endpoints.",
    "Active agents are never deleted.",
    "Run me again: nothing changes.",
  ];
  let tip = 0;
  const nextTip = () => TIPS[tip++ % TIPS.length];

  // ---------------------------------------------------------------- hero ---
  // A field of agents with problems; the harrier quarters it row by row
  // (low sweeps, turning at each edge) and fixes what it passes over.
  const HOSTS = ["FIN-07", "HR-LT12", "WEB-01", "DB-02", "POS-114", "LAB-3", "SALES-9", "DC-01", "OPS-LT4", "KIOSK-2", "DEV-31", "MAIL-1"];
  const FIXES = {
    down: ["G", "agent hung 12 min, restarted"],
    twin: ["E", "renamed: old record removed"],
    nic: ["I", "new network cards: records tied"],
    ghost: ["stale", "gone 30 days, record removed"],
  };

  function patrol(root) {
    const grid = root.querySelector(".field-grid");
    const log = root.querySelector(".field-log");
    const again = root.querySelector(".field-again");
    const count = root.querySelector(".field-count");
    const bird = new Bird(root, 3, "field-bird");
    let tiles = [];
    let records = 0;
    let running = false;
    let patrolled = false;
    let width = root.clientWidth;

    function build() {
      const cols = Math.max(6, Math.min(12, Math.floor((grid.clientWidth + 10) / 40)));
      grid.style.setProperty("--cols", cols);
      grid.textContent = "";
      log.textContent = "";
      let seed = 11;
      const rand = () => (seed = (seed * 16807) % 2147483647) / 2147483647;
      const kinds = ["twin", "down", "ghost", "nic"];
      let k = 0;
      tiles = [];
      for (let r = 0; r < 4; r++) {
        for (let c = 0; c < cols; c++) {
          const kind = rand() < 0.2 ? kinds[k++ % kinds.length] : "ok";
          const el = document.createElement("span");
          el.className = "tile";
          el.dataset.kind = kind;
          grid.append(el);
          tiles.push({ el, r, kind, host: HOSTS[(r * cols + c) % HOSTS.length], done: false });
        }
      }
      // Twins are two records for one machine.
      records = tiles.length + tiles.filter((t) => t.kind === "twin" || t.kind === "nic").length;
      count.textContent = `${records} records`;
    }

    function at(el) {
      const a = el.getBoundingClientRect();
      const b = root.getBoundingClientRect();
      return { x: a.left - b.left + a.width / 2, y: a.top - b.top + a.height / 2 };
    }
    const perch = () => ({ x: root.clientWidth - bird.w - 28, y: -bird.h + 2 });

    function fix(t, animate = true) {
      t.done = true;
      const kind = t.kind === "ghost" ? "gone" : "ok";
      if (animate) {
        t.el.classList.add("fixing");
        setTimeout(() => {
          t.el.classList.remove("fixing");
          t.el.dataset.kind = kind;
        }, 360);
      } else t.el.dataset.kind = kind;
      if (t.kind !== "down") records -= 1;
      count.textContent = `${records} records`;
      const [code, text] = FIXES[t.kind];
      const li = document.createElement("li");
      li.innerHTML = `<b>${code}</b><span>${t.host}</span><span>${text}</span>`;
      log.append(li);
      while (log.children.length > 4) log.firstElementChild.remove();
    }

    // Straight runs along each row, half-circle turns outside the field.
    function route() {
      const centers = tiles.map((t) => ({ t, ...at(t.el) }));
      const rows = [0, 1, 2, 3].map((r) => centers.find((c) => c.t.r === r).y - bird.h / 2 - 8);
      const left = -bird.w - 24;
      const right = root.clientWidth + 24;
      const segs = [];
      let pos = { x: bird.x, y: bird.y };
      const line = (x, y) => {
        segs.push({ x0: pos.x, y0: pos.y, x1: x, y1: y, len: Math.hypot(x - pos.x, y - pos.y) });
        pos = { x, y };
      };
      const turn = (y, dir) => {
        const rad = Math.abs(y - pos.y) / 2;
        segs.push({ turn: true, x: pos.x, cy: (pos.y + y) / 2, rad, dir, len: Math.PI * rad });
        pos = { x: pos.x, y };
      };
      line(left, rows[0]);
      rows.forEach((y, r) => {
        const dir = r % 2 ? -1 : 1;
        line(dir > 0 ? right : left, y);
        if (r < rows.length - 1) turn(rows[r + 1], dir);
      });
      const p = perch();
      line(p.x, p.y);
      return { segs, centers };
    }

    function fly({ segs, centers }) {
      const total = segs.reduce((a, s) => a + s.len, 0);
      const speed = Math.max(240, root.clientWidth * 0.5);
      return new Promise((done) => {
        let start = 0;
        bird.flap();
        const place = (s, d) => {
          let x, y, dx;
          if (s.turn) {
            const th = (Math.PI * d) / s.len;
            x = s.x + s.dir * s.rad * Math.sin(th);
            y = s.cy - s.rad * Math.cos(th);
            dx = s.dir * Math.cos(th);
          } else {
            const k = s.len ? d / s.len : 1;
            x = s.x0 + (s.x1 - s.x0) * k;
            y = s.y0 + (s.y1 - s.y0) * k;
            dx = s.x1 - s.x0;
          }
          if (Math.abs(dx) > 0.05) bird.face(dx);
          bird.moveTo(x, y);
          const cx = x + bird.w / 2;
          const cy = y + bird.h / 2 + 8;
          for (const c of centers) {
            if (!c.t.done && c.t.kind !== "ok" && Math.abs(c.x - cx) < 16 && Math.abs(c.y - cy) < 14) fix(c.t);
          }
        };
        const frame = (now) => {
          start ||= now;
          let d = ((now - start) / 1000) * speed;
          if (d >= total) {
            place(segs.at(-1), segs.at(-1).len);
            bird.face(-1);
            bird.sit();
            return done();
          }
          let i = 0;
          while (d > segs[i].len) d -= segs[i++].len;
          place(segs[i], d);
          requestAnimationFrame(frame);
        };
        requestAnimationFrame(frame);
      });
    }

    async function run() {
      if (running) return;
      running = true;
      again.disabled = true;
      if (tiles.some((t) => t.done)) build();
      await fly(route());
      patrolled = true;
      await bird.wave(3);
      bird.say("All clear.");
      bird.idle();
      running = false;
      again.disabled = false;
    }

    // The finished field, drawn without animation.
    function settle() {
      patrolled = true;
      for (const t of tiles) if (t.kind !== "ok" && !t.done) fix(t, false);
      const p = perch();
      bird.face(-1);
      bird.moveTo(p.x, p.y);
    }

    build();
    bird.el.addEventListener("click", () => {
      if (running) return;
      bird.wave(2);
      bird.say(nextTip());
    });
    again.addEventListener("click", run);
    // Only a new width changes the layout (mobile browsers also fire resize
    // when their toolbars slide in and out).
    addEventListener("resize", () => {
      if (running || root.clientWidth === width) return;
      width = root.clientWidth;
      build();
      if (patrolled) settle();
      else bird.moveTo(-bird.w - 24, 0);
    });

    if (still) {
      settle();
      again.hidden = true;
      return;
    }
    bird.moveTo(-bird.w - 24, 0);
    new IntersectionObserver((entries, io) => {
      if (entries[0].isIntersecting) {
        io.disconnect();
        setTimeout(run, 500);
      }
    }, { threshold: 0.4 }).observe(root);
  }

  // ---------------------------------------------- docs reading progress ---
  // A wire along the bottom edge of the screen fills as you read; the bird
  // flies along it while the page scrolls (facing the scroll direction) and
  // perches on it when scrolling stops.
  function progress(bar) {
    const fill = bar.querySelector(".progress-fill");
    const bird = new Bird(bar, 2, "progress-bird");
    let last = scrollY;
    let rest = 0;
    let queued = false;
    const update = () => {
      queued = false;
      const max = document.documentElement.scrollHeight - innerHeight;
      const p = max > 0 ? Math.min(1, Math.max(0, scrollY / max)) : 0;
      fill.style.transform = `scaleX(${p})`;
      bird.moveTo(p * (bar.clientWidth - bird.w), -bird.h + 1);
    };
    addEventListener(
      "scroll",
      () => {
        const dy = scrollY - last;
        last = scrollY;
        if (!still && dy) {
          if (!bird.timer) bird.flap();
          bird.face(dy);
          clearTimeout(rest);
          rest = setTimeout(() => {
            bird.sit();
            bird.idle();
          }, 280);
        }
        if (!queued) {
          queued = true;
          requestAnimationFrame(update);
        }
      },
      { passive: true },
    );
    addEventListener("resize", update);
    update();
    bird.idle();
  }

  // ------------------------------------------------------ perched birds ---
  function perched(host) {
    const bird = new Bird(host, Number(host.dataset.bird) || 2, "perched");
    host.addEventListener("mouseenter", () => bird.wave(2));
    if (host.hasAttribute("data-talk")) {
      bird.el.addEventListener("click", () => {
        bird.wave(2);
        bird.say(nextTip());
      });
    }
    if (host.hasAttribute("data-idle")) bird.idle();
  }

  document.querySelectorAll(".field").forEach(patrol);
  document.querySelectorAll(".progress").forEach(progress);
  document.querySelectorAll("[data-bird]").forEach(perched);
})();
