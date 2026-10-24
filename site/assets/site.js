// Theme, sidebar, install tabs, copy buttons, docs search and section
// tracking. Preferences are a per-browser convenience: everything works
// when storage is unavailable.
(() => {
  "use strict";

  const root = document.documentElement;
  const store = {
    get: (k) => {
      try {
        return localStorage.getItem(k);
      } catch {
        return null;
      }
    },
    set: (k, v) => {
      try {
        localStorage.setItem(k, v);
      } catch {
        /* private mode: keep it for this page only */
      }
    },
  };

  // ------------------------------------------------------------- theme ---
  const light = matchMedia("(prefers-color-scheme: light)");
  const themeButtons = document.querySelectorAll("[data-theme-toggle]");
  function showTheme() {
    const isLight = root.dataset.theme === "light";
    themeButtons.forEach((b) => {
      b.setAttribute("aria-pressed", String(isLight));
      b.setAttribute("aria-label", isLight ? "Switch to dark theme" : "Switch to light theme");
    });
  }
  themeButtons.forEach((b) =>
    b.addEventListener("click", () => {
      root.dataset.theme = root.dataset.theme === "light" ? "dark" : "light";
      store.set("harrier-theme", root.dataset.theme);
      showTheme();
    }),
  );
  light.addEventListener("change", () => {
    if (store.get("harrier-theme")) return;
    root.dataset.theme = light.matches ? "light" : "dark";
    showTheme();
  });
  showTheme();

  // ----------------------------------------------------------- sidebar ---
  // Wide screens: the sidebar sits beside the text and can be hidden.
  // Narrow screens: it is a drawer over the page.
  const toggle = document.querySelector("[data-sidebar-toggle]");
  const sidebar = document.getElementById("sidebar");
  if (toggle && sidebar) {
    const narrow = matchMedia("(max-width: 960px)");
    const isOpen = () => (narrow.matches ? root.dataset.drawer === "open" : root.dataset.sidebar !== "hidden");
    const label = () => {
      const open = isOpen();
      toggle.setAttribute("aria-expanded", String(open));
      toggle.setAttribute("aria-label", open ? "Hide navigation" : "Show navigation");
      sidebar.inert = narrow.matches && !open;
    };
    const set = (open) => {
      if (narrow.matches) {
        root.dataset.drawer = open ? "open" : "";
        if (open) sidebar.querySelector("a, input")?.focus();
      } else {
        root.dataset.sidebar = open ? "" : "hidden";
        store.set("harrier-sidebar", open ? "shown" : "hidden");
      }
      label();
    };
    if (store.get("harrier-sidebar") === "hidden") root.dataset.sidebar = "hidden";
    toggle.addEventListener("click", () => set(!isOpen()));
    document.querySelector(".drawer-backdrop")?.addEventListener("click", () => set(false));
    sidebar.addEventListener("click", (e) => {
      if (narrow.matches && e.target.closest("a")) set(false);
    });
    addEventListener("keydown", (e) => {
      if (e.key === "Escape" && narrow.matches && isOpen()) {
        set(false);
        toggle.focus();
      }
    });
    narrow.addEventListener("change", () => {
      root.dataset.drawer = "";
      label();
    });
    label();
  }

  // ------------------------------------------------------- install tabs ---
  document.querySelectorAll("[role=tablist]").forEach((list) => {
    const tabs = [...list.querySelectorAll("[role=tab]")];
    const select = (tab) => {
      tabs.forEach((t) => {
        const on = t === tab;
        t.setAttribute("aria-selected", String(on));
        t.tabIndex = on ? 0 : -1;
        document.getElementById(t.getAttribute("aria-controls")).hidden = !on;
      });
    };
    tabs.forEach((t, i) => {
      t.addEventListener("click", () => select(t));
      t.addEventListener("keydown", (e) => {
        const step = { ArrowRight: 1, ArrowLeft: -1 }[e.key];
        if (!step) return;
        const next = tabs[(i + step + tabs.length) % tabs.length];
        select(next);
        next.focus();
      });
    });
  });

  // ------------------------------------------------------- copy buttons ---
  document.querySelectorAll("pre").forEach((pre) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "copy";
    button.textContent = "Copy";
    button.addEventListener("click", async () => {
      const text = pre.querySelector("code")?.innerText ?? pre.innerText;
      try {
        await navigator.clipboard.writeText(text.trim());
        button.textContent = "Copied";
      } catch {
        getSelection().selectAllChildren(pre.querySelector("code") ?? pre);
        button.textContent = "Press Ctrl+C";
      }
      setTimeout(() => (button.textContent = "Copy"), 1800);
    });
    pre.append(button);
  });

  // -------------------------------------------------- heading anchors ---
  document.querySelectorAll(".doc section[id] > :is(h2, h3)").forEach((h) => {
    const a = document.createElement("a");
    a.className = "anchor";
    a.href = `#${h.parentElement.id}`;
    a.setAttribute("aria-label", `Link to ${h.textContent}`);
    a.textContent = "#";
    h.append(a);
  });

  // ----------------------------------------------------------- search ---
  const search = document.getElementById("search");
  if (search) {
    const links = [...document.querySelectorAll(".sidebar nav a[href^='#']")];
    const text = new Map(links.map((a) => [a, document.querySelector(a.hash)?.textContent.toLowerCase() ?? ""]));
    const empty = document.querySelector(".search-empty");
    search.addEventListener("input", () => {
      const q = search.value.trim().toLowerCase();
      let shown = 0;
      for (const a of links) {
        const hit = !q || text.get(a).includes(q) || a.textContent.toLowerCase().includes(q);
        a.parentElement.hidden = !hit;
        shown += hit;
      }
      document.querySelectorAll(".sidebar nav .group").forEach((g) => {
        g.hidden = !g.querySelector("li:not([hidden])");
      });
      empty.hidden = shown > 0;
      empty.textContent = shown ? "" : `No section mentions “${search.value.trim()}”. Try a command such as setup-server.`;
    });
    search.addEventListener("keydown", (e) => {
      if (e.key !== "Enter") return;
      const first = links.find((a) => !a.parentElement.hidden);
      if (first) location.hash = first.hash;
    });
    addEventListener("keydown", (e) => {
      if (e.key === "/" && !e.target.closest("input, textarea")) {
        e.preventDefault();
        if (root.dataset.sidebar === "hidden") toggle?.click();
        search.focus();
      }
    });
  }

  // --------------------------------------------- current section in nav ---
  const navLinks = new Map([...document.querySelectorAll(".sidebar nav a[href^='#']")].map((a) => [a.hash.slice(1), a]));
  if (navLinks.size) {
    const visible = new Set();
    const mark = () => {
      const ids = [...navLinks.keys()].filter((id) => visible.has(id));
      const current = ids.at(-1);
      navLinks.forEach((a, id) => (id === current ? a.setAttribute("aria-current", "true") : a.removeAttribute("aria-current")));
    };
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => (e.isIntersecting ? visible.add(e.target.id) : visible.delete(e.target.id)));
        mark();
      },
      { rootMargin: "-80px 0px -65% 0px" },
    );
    navLinks.forEach((_, id) => {
      const el = document.getElementById(id);
      if (el) io.observe(el);
    });
  }
})();
