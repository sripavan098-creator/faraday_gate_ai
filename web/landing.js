/* Landing page behaviour.
   Extracted from the inline <script> blocks so the site CSP (no 'unsafe-inline')
   can stay locked down. The WebGL scene is an illustration, not live data; the
   threat feed it drives is labelled SIMULATED in the markup and in CSS. */

(() => {
  "use strict";

  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const canvas = document.getElementById("gl");

  if (window.THREE) {
    startScene(canvas, reduced);
  }

  decryptHeadings(reduced);
  startClock();

  function startScene(cv, still) {
    let renderer;
    try {
      renderer = new THREE.WebGLRenderer({ canvas: cv, antialias: true });
    } catch (err) {
      cv.style.display = "none";
      return;
    }

    renderer.setPixelRatio(Math.min(devicePixelRatio || 1, 2));
    renderer.setClearColor(0x060708, 1);

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, 1, 0.1, 100);
    const steel = new THREE.Color(0x2fd67f);
    const hot = new THREE.Color(0xff4a1c);

    /* the cage */
    const half = 2.5;
    const n = 8;
    const step = (2 * half) / n;
    const positions = [];
    const seg = (a, b) => positions.push(...a, ...b);

    for (let i = 0; i <= n; i++) {
      const u = -half + i * step;
      for (const s of [-half, half]) {
        seg([u, -half, s], [u, half, s]);
        seg([-half, u, s], [half, u, s]);
        seg([s, u, -half], [s, u, half]);
        seg([s, -half, u], [s, half, u]);
        seg([u, s, -half], [u, s, half]);
        seg([-half, s, u], [half, s, u]);
      }
    }

    const cageGeo = new THREE.BufferGeometry();
    cageGeo.setAttribute("position", new THREE.Float32BufferAttribute(positions, 3));
    const cageMat = new THREE.LineBasicMaterial({
      color: steel,
      transparent: true,
      opacity: 0.3,
    });
    scene.add(new THREE.LineSegments(cageGeo, cageMat));

    /* repository (left) and agent (right) */
    const wire = (geo, x, color) => {
      const mesh = new THREE.LineSegments(
        new THREE.EdgesGeometry(geo),
        new THREE.LineBasicMaterial({ color: color })
      );
      mesh.position.x = x;
      scene.add(mesh);
      return mesh;
    };

    const repo = wire(new THREE.BoxGeometry(2.2, 3, 2.2), -10, 0x3dff8f);
    const agent = wire(new THREE.IcosahedronGeometry(1.5, 0), 10, 0x3dff8f);

    scene.fog = new THREE.Fog(0x060708, 16, 48);

    const grid = new THREE.GridHelper(90, 90, 0x14532d, 0x0c2a1a);
    grid.position.y = -3.4;
    scene.add(grid);

    const beam = new THREE.Mesh(
      new THREE.PlaneGeometry(5, 5),
      new THREE.MeshBasicMaterial({
        color: 0x3dff8f,
        transparent: true,
        opacity: 0.1,
        side: THREE.DoubleSide,
      })
    );
    beam.rotation.y = Math.PI / 2;
    scene.add(beam);

    /* packets */
    const count = innerWidth < 700 ? 420 : 900;
    const points = new Float32Array(count * 3);
    const colors = new Float32Array(count * 3);
    const velocity = [];
    const blockedPacket = [];
    const reversed = [];
    const seen = [];

    const spawn = (i) => {
      points[i * 3] = -18 - Math.random() * 16;
      points[i * 3 + 1] = (Math.random() - 0.5) * 4.6;
      points[i * 3 + 2] = (Math.random() - 0.5) * 4.6;
      velocity[i] = [0.05 + Math.random() * 0.07, 0, 0];
      blockedPacket[i] = Math.random() < 0.22;
      reversed[i] = false;
      seen[i] = false;
      const c = blockedPacket[i] ? hot : new THREE.Color(0x3dff8f);
      colors.set([c.r, c.g, c.b], i * 3);
    };

    for (let i = 0; i < count; i++) {
      spawn(i);
      points[i * 3] += Math.random() * 34;
    }

    const packetGeo = new THREE.BufferGeometry();
    packetGeo.setAttribute("position", new THREE.BufferAttribute(points, 3));
    packetGeo.setAttribute("color", new THREE.BufferAttribute(colors, 3));
    scene.add(
      new THREE.Points(
        packetGeo,
        new THREE.PointsMaterial({
          size: 0.11,
          vertexColors: true,
          transparent: true,
          opacity: 0.95,
        })
      )
    );

    /* camera path driven by scroll */
    const CAM = [
      [0, 1.4, 15],
      [-8.5, 2.2, 7.5],
      [1, 0.6, 6.2],
      [7, 2.8, 11],
    ];
    const LOOK = [
      [0, 0, 0],
      [-3, 0, 0],
      [0, 0, 0],
      [1, 0, 0],
    ];

    let mouseX = 0;
    let mouseY = 0;
    let flash = 0;
    let blocked = 0;
    let passed = 0;
    let previous = "genesis";

    addEventListener("pointermove", (e) => {
      mouseX = e.clientX / innerWidth - 0.5;
      mouseY = e.clientY / innerHeight - 0.5;
    });

    const smooth = (t) => t * t * (3 - 2 * t);
    const lerp = (a, b, t) => a.map((v, i) => v + (b[i] - v) * t);
    const $ = (id) => document.getElementById(id);

    const sha = async (text) => {
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
      return [...new Uint8Array(digest)]
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    };

    async function chain() {
      previous = await sha(previous + "|" + blocked);
      $("hh").textContent = previous.slice(0, 8);
    }

    const feedEl = $("feed");
    function feed(kind, message) {
      const row = document.createElement("div");
      const stamp = new Date().toTimeString().slice(0, 8);
      row.className = kind === "BLOCK" ? "b" : "p";
      row.textContent = "[" + stamp + "] " + kind + "  " + message;
      feedEl.appendChild(row);
      while (feedEl.children.length > 7) {
        feedEl.removeChild(feedEl.firstChild);
      }
    }

    function size() {
      renderer.setSize(innerWidth, innerHeight, false);
      camera.aspect = innerWidth / innerHeight;
      camera.updateProjectionMatrix();
    }

    function frame() {
      const max = document.documentElement.scrollHeight - innerHeight;
      const p = max > 0 ? scrollY / max : 0;
      const t = Math.min(p, 1) * (CAM.length - 1);
      const i = Math.min(Math.floor(t), CAM.length - 2);
      const f = smooth(t - i);

      const eye = lerp(CAM[i], CAM[i + 1], f);
      const look = lerp(LOOK[i], LOOK[i + 1], f);

      camera.position.set(eye[0] + mouseX * 1.6, eye[1] - mouseY * 1.2, eye[2]);
      camera.lookAt(look[0], look[1], look[2]);

      repo.rotation.y += 0.004;
      beam.position.x = Math.sin(performance.now() / 2200) * 11;
      agent.rotation.y -= 0.006;
      agent.rotation.x += 0.003;

      cageMat.color.copy(steel).lerp(hot, flash);
      cageMat.opacity = 0.3 + flash * 0.55;
      flash *= 0.9;

      for (let k = 0; k < count; k++) {
        const v = velocity[k];
        const j = k * 3;
        const x0 = points[j];
        points[j] += v[0];
        points[j + 1] += v[1];
        points[j + 2] += v[2];
        const x = points[j];

        if (blockedPacket[k] && !reversed[k] && x0 < -half && x >= -half) {
          reversed[k] = true;
          velocity[k] = [
            -0.11,
            (Math.random() - 0.5) * 0.09,
            (Math.random() - 0.5) * 0.09,
          ];
          flash = 1;
          blocked++;
          chain();
          feed(
            "BLOCK",
            Math.random() < 0.4
              ? "prompt injection \u00b7 README.md:5"
              : "secret \u00b7 src/config.py:" + (2 + (blocked % 2))
          );
        } else if (!blockedPacket[k] && !seen[k] && x0 < half && x >= half) {
          seen[k] = true;
          passed++;
          if (passed % 9 === 0) {
            feed("PASS", "clean chunk forwarded");
          }
        }

        if (x > 18 || x < -36) {
          spawn(k);
        }
      }

      packetGeo.attributes.position.needsUpdate = true;
      $("nb").textContent = blocked;
      $("np").textContent = passed;
      renderer.render(scene, camera);
    }

    function loop() {
      frame();
      requestAnimationFrame(loop);
    }

    size();
    addEventListener("resize", () => {
      size();
      if (still) {
        frame();
      }
    });

    if (still) {
      for (let s = 0; s < 220; s++) {
        frame();
      }
      addEventListener("scroll", frame);
    } else {
      loop();
    }
  }

  /* Heading decode effect */
  function decryptHeadings(still) {
    const GLYPHS = "\u2588\u2593\u2592\u2591#$%&*+<>/";

    function decode(el) {
      if (el.dataset.d) {
        return;
      }
      el.dataset.d = "1";
      if (still) {
        return;
      }

      const text = el.textContent;
      let f = 0;
      const id = setInterval(() => {
        f++;
        el.textContent = [...text]
          .map((c, i) => {
            if (c === " " || c === ".") {
              return c;
            }
            return i < f / 1.4 ? c : GLYPHS[Math.floor(Math.random() * GLYPHS.length)];
          })
          .join("");
        if (f / 1.4 >= text.length) {
          el.textContent = text;
          clearInterval(id);
        }
      }, 30);
    }

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            decode(entry.target);
          }
        });
      },
      { threshold: 0.6 }
    );

    document.querySelectorAll(".dc").forEach((el) => observer.observe(el));
  }

  function startClock() {
    const tick = () => {
      const el = document.getElementById("clk");
      if (el) {
        el.textContent = new Date().toTimeString().slice(0, 8);
      }
    };
    tick();
    setInterval(tick, 1000);
  }
})();
