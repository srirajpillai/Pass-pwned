/* ==========================================================================
   Password Strength Analyser & Breach Checker - client side engine

   PRIVACY: the SHA-1 digest is computed here, in the browser.  Only the first
   five characters of the digest are sent to /api/range/<prefix>; the suffix
   comparison happens below, in matchSuffix().  The server therefore never
   receives the password or its complete digest.
   ========================================================================== */

(function () {
  "use strict";

  /* ------------------------------------------------------------ theme ---- */
  const THEME_KEY = "psa-theme";
  const root = document.documentElement;

  function applyTheme(t) {
    root.setAttribute("data-theme", t);
    const btn = document.getElementById("themeToggle");
    if (btn) {
      btn.textContent = t === "dark" ? "☀" : "☾";
      btn.setAttribute("aria-label",
        t === "dark" ? "Switch to light theme" : "Switch to dark theme");
    }
  }

  const stored = localStorage.getItem(THEME_KEY);
  applyTheme(stored || (window.matchMedia &&
    window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"));

  document.addEventListener("click", (e) => {
    if (e.target.closest("#themeToggle")) {
      const next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
      applyTheme(next);
      localStorage.setItem(THEME_KEY, next);
    }
  });

  /* ------------------------------------------------------- common words -- */
  const COMMON = [
    "123456", "123456789", "12345678", "1234567890", "1234567", "12345",
    "1234", "123123", "111111", "000000", "password", "password1",
    "password123", "passw0rd", "passwd", "p@ssword", "qwerty", "qwerty123",
    "qwertyuiop", "qwerty1", "abc123", "admin", "admin123", "letmein",
    "welcome", "welcome1", "monkey", "dragon", "sunshine", "princess",
    "football", "baseball", "iloveyou", "shadow", "master", "superman",
    "trustno1", "1q2w3e4r", "zxcvbnm", "asdfgh", "login", "hello", "secret",
    "starwars", "whatever", "internet", "computer", "michael", "jordan",
    "harley", "ranger", "hunter", "buster", "thomas", "summer", "winter",
    "freedom", "chocolate", "password@123", "india", "mumbai", "delhi"
  ];
  const COMMON_SET = new Set(COMMON);

  const KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"];

  const LEET = {
    "4": "a", "@": "a", "8": "b", "(": "c", "{": "c", "[": "c",
    "3": "e", "6": "g", "9": "g", "1": "l", "!": "i", "|": "i",
    "0": "o", "5": "s", "$": "s", "7": "t", "+": "t", "2": "z"
  };

  const GUESSES_PER_SECOND = 1e10;

  /* ------------------------------------------------------------ helpers -- */
  function deLeet(pwd) {
    return pwd.split("").map(c => LEET[c] || c).join("").toLowerCase();
  }

  function charsetSize(pwd) {
    let pool = 0;
    if (/[a-z]/.test(pwd)) pool += 26;
    if (/[A-Z]/.test(pwd)) pool += 26;
    if (/[0-9]/.test(pwd)) pool += 10;
    if (/[^A-Za-z0-9]/.test(pwd)) pool += 33;
    return Math.max(pool, 1);
  }

  function effectiveLength(pwd) {
    if (!pwd.length) return 0;
    var low = pwd.toLowerCase();
    var n = 1;
    for (var i = 1; i < low.length; i++) {
      var a = low[i - 1], b = low[i];
      var alnum = function (c) { return /[a-z0-9]/.test(c); };
      if (a === b) continue;                                   // repeat
      if (alnum(a) && alnum(b) && Math.abs(b.charCodeAt(0) - a.charCodeAt(0)) === 1) {
        continue;                                              // +1 / -1 step
      }
      n += 1;
    }
    return Math.max(n, 1);
  }

  function entropyBits(pwd) {
    if (!pwd.length) return 0;
    return effectiveLength(pwd) * (Math.log(charsetSize(pwd)) / Math.LN2);
  }

  function longestRun(pwd, alphabet) {
    let best = 0;
    const low = pwd.toLowerCase();
    [alphabet, alphabet.split("").reverse().join("")].forEach(function (dir) {
      let run = 1;
      for (let i = 1; i < low.length; i++) {
        const a = low[i - 1], b = low[i];
        if (dir.indexOf(a) >= 0 && dir.indexOf(b) >= 0 &&
            dir.indexOf(b) - dir.indexOf(a) === 1) {
          run += 1; best = Math.max(best, run);
        } else {
          run = 1;
        }
      }
    });
    return best;
  }

  function isDigitSequence(pwd) {
    return /0123|1234|2345|3456|4567|5678|6789|7890|0987|9876|8765|7654|6543|5432|4321|3210/
      .test(pwd);
  }

  function keyboardWalk(pwd) {
    return KEYBOARD_ROWS.some(row => longestRun(pwd, row) >= 4);
  }

  function longestRepeat(pwd) {
    let best = 1, run = 1;
    for (let i = 1; i < pwd.length; i++) {
      if (pwd[i] === pwd[i - 1]) { run += 1; best = Math.max(best, run); }
      else { run = 1; }
    }
    return best;
  }

  function stripNonAlpha(s) { return s.toLowerCase().replace(/[^a-z]/g, ""); }

  function hasCommonWord(pwd) {
    const norm = stripNonAlpha(deLeet(pwd));
    if (COMMON_SET.has(norm)) return true;
    for (let i = 0; i < COMMON.length; i++) {
      const w = stripNonAlpha(COMMON[i]);
      if (w.length >= 4 && norm.indexOf(w) !== -1) return true;
    }
    return false;
  }

  const UNITS = [
    [1, "second"], [60, "minute"], [3600, "hour"],
    [86400, "day"], [2592000, "month"], [31536000, "year"]
  ];

  function humanise(seconds) {
    if (seconds < 1) return "instant";
    let limit = 1, name = "second";
    for (let i = 0; i < UNITS.length; i++) {
      if (seconds / UNITS[i][0] >= 1) { limit = UNITS[i][0]; name = UNITS[i][1]; }
      else break;
    }
    const value = seconds / limit;
    if (name === "year" && value > 1000) return "centuries";
    const text = value < 10
      ? (Math.round(value * 10) / 10).toString()
      : Math.round(value).toLocaleString();
    return text + " " + name + (text === "1" ? "" : "s");
  }

  function crackTime(bits) {
    const guesses = Math.pow(2, Math.max(bits - 1, 0));
    return humanise(guesses / GUESSES_PER_SECOND);
  }

  const VERDICTS = [
    [0, 20, "Very Weak", "danger"],
    [21, 40, "Weak", "warn"],
    [41, 60, "Fair", "warn"],
    [61, 80, "Strong", "ok"],
    [81, 100, "Excellent", "ok"]
  ];

  /* ------------------------------------------------------------ analyse -- */
  function analyse(pwd) {
    const length = pwd.length;
    if (!length) {
      return {
        length: 0, score: 0, verdict: "Very Weak", tone: "danger",
        entropy_bits: 0, charset_size: 0, crack_time: "instant",
        patterns: [], suggestions: [], checks: []
      };
    }

    const entropy = entropyBits(pwd);
    const charset = charsetSize(pwd);
    let score = Math.min(100, entropy * 2.6);
    const patterns = [];

    function add(name, detail, penalty) {
      patterns.push({ name: name, detail: detail, penalty: penalty });
      score -= penalty;
    }

    const lower = pwd.toLowerCase();
    if (COMMON_SET.has(lower) || COMMON_SET.has(deLeet(pwd))) {
      add("Found in common password list",
        "This exact password is one of the most frequently used passwords in the world.",
        45);
    } else if (hasCommonWord(pwd)) {
      add("Contains a common word",
        "Dictionary words are tried first by every cracking tool.", 30);
    }

    if (isDigitSequence(pwd)) {
      add("Number sequence",
        "Contains a run of consecutive digits (e.g. 1234, 9876).", 22);
    }
    if (longestRun(pwd, "abcdefghijklmnopqrstuvwxyz") >= 4) {
      add("Letter sequence",
        "Contains four or more consecutive letters (e.g. abcd).", 20);
    }
    if (keyboardWalk(pwd)) {
      add("Keyboard walk",
        "Follows a straight line across the keyboard (e.g. qwer, asdf).", 24);
    }

    const reps = longestRepeat(pwd);
    if (reps >= 3) {
      let ch = pwd[0];
      for (let i = 1; i < pwd.length; i++) {
        if (pwd[i] === pwd[i - 1]) { ch = pwd[i]; break; }
      }
      add("Repeated characters",
        "The character '" + ch + "' repeats " + reps + " times in a row.", 18);
    }

    if (/(19\d{2}|20\d{2})/.test(pwd)) {
      add("Contains a year",
        "Birth years and calendar years are among the first things a cracker appends.",
        14);
    }

    if (length < 8) {
      add("Too short",
        "Passwords below 8 characters are trivially brute forced.", 25);
    } else if (length < 12) {
      add("Could be longer",
        "Length is the single biggest factor in resisting an offline attack.", 8);
    }

    const checks = [
      ["Lowercase letter", /[a-z]/.test(pwd)],
      ["Uppercase letter", /[A-Z]/.test(pwd)],
      ["Digit", /[0-9]/.test(pwd)],
      ["Symbol", /[^A-Za-z0-9]/.test(pwd)],
      ["12 or more characters", length >= 12],
      ["No common word", !hasCommonWord(pwd)]
    ];
    const missing = checks.filter(c => !c[1]).map(c => c[0]);
    if (missing.length >= 3) {
      add("Low character variety",
        "Missing: " + missing.slice(0, 3).join(", ") + ".", 10);
    }

    score = Math.max(0, Math.min(100, Math.round(score)));
    if (patterns.length === 0 && length >= 12) score = Math.max(score, 82);

    let verdict = "Very Weak", tone = "danger";
    for (let i = 0; i < VERDICTS.length; i++) {
      if (score >= VERDICTS[i][0] && score <= VERDICTS[i][1]) {
        verdict = VERDICTS[i][2]; tone = VERDICTS[i][3]; break;
      }
    }

    const suggestions = [];
    if (length < 12) {
      suggestions.push("Use at least 12 characters - length beats complexity rules.");
    }
    if (hasCommonWord(pwd)) {
      suggestions.push("Avoid dictionary words, even with numbers or symbols attached.");
    }
    if (patterns.some(p => p.name === "Keyboard walk")) {
      suggestions.push("Do not use keys that sit next to each other.");
    }
    if (patterns.some(p => p.name === "Repeated characters")) {
      suggestions.push("Avoid repeating the same character.");
    }
    if (suggestions.length === 0) {
      suggestions.push("Good. Store it in a password manager and never reuse it on another site.");
    }

    return {
      length: length,
      score: score,
      verdict: verdict,
      tone: tone,
      entropy_bits: Math.round(entropy * 10) / 10,
      charset_size: charset,
      crack_time: crackTime(entropy),
      patterns: patterns,
      suggestions: suggestions,
      checks: checks.map(c => ({ label: c[0], passed: !!c[1] }))
    };
  }

  /* ---------------------------------------------------------- sha1 + API -- */
  async function sha1Hex(str) {
    const buf = new TextEncoder().encode(str);
    const digest = await crypto.subtle.digest("SHA-1", buf);
    return Array.from(new Uint8Array(digest))
      .map(b => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  }

  async function lookupBreach(password) {
    if (!crypto.subtle) {
      return { available: false, reason: "insecure-context",
               breached: null, count: 0, source: "unavailable", prefix: "" };
    }
    const digest = await sha1Hex(password);
    const prefix = digest.slice(0, 5);
    const suffix = digest.slice(5);
    try {
      const res = await fetch("/api/range/" + prefix);
      if (!res.ok) throw new Error("range request failed");
      const data = await res.json();
      if (!data.available) {
        return { available: false, reason: "offline", breached: null,
                 count: 0, source: "unavailable", prefix: prefix };
      }
      const count = (data.suffixes && data.suffixes[suffix]) || 0;
      return { available: true, breached: count > 0, count: count,
               source: data.source || "hibp", prefix: prefix };
    } catch (err) {
      return { available: false, reason: "network", breached: null,
               count: 0, source: "unavailable", prefix: prefix };
    }
  }

  /* ------------------------------------------------------------- render -- */
  const el = id => document.getElementById(id);

  const TONE_VAR = { danger: "var(--red)", warn: "var(--amber)", ok: "var(--green)" };

  function renderMeter(score, tone) {
    const segs = document.querySelectorAll("#meter .seg");
    segs.forEach((s, i) => {
      s.className = "seg";
      if (score >= (i + 1) * 20 - 12) s.classList.add("on", tone);
    });
  }

  function crackMethod(result) {
    const names = result.patterns.map(p => p.name);
    if (names.indexOf("Found in common password list") !== -1) {
      return "A cracking tool will try this password very early because it is already in common password lists.";
    }
    if (names.indexOf("Contains a common word") !== -1) {
      return "A dictionary attack can try the word first, then add likely numbers and symbols.";
    }
    if (names.indexOf("Keyboard walk") !== -1) {
      return "A pattern attack can test nearby keyboard keys such as rows, columns, and walks.";
    }
    if (names.indexOf("Number sequence") !== -1 ||
        names.indexOf("Letter sequence") !== -1 ||
        names.indexOf("Repeated characters") !== -1 ||
        names.indexOf("Contains a year") !== -1) {
      return "A pattern attack can test the sequence, repeated characters, or year before trying random combinations.";
    }
    if (names.indexOf("Too short") !== -1 || names.indexOf("Could be longer") !== -1) {
      return "A brute-force attack has fewer combinations to test because the password is short.";
    }
    return "No obvious shortcut was found. An attacker would need a broader brute-force search.";
  }

  function render(result, breach) {
    el("emptyState").style.display = "none";
    el("resultPanel").style.display = "block";
    el("breachCard").style.display = "block";

    const colour = TONE_VAR[result.tone] || "var(--text)";
    el("scoreVal").textContent = result.score;
    el("scoreVal").style.color = colour;
    el("verdictText").textContent = result.verdict;
    el("verdictText").style.color = colour;
    renderMeter(result.score, result.tone);

    el("kLength").textContent = result.length + " chars";
    el("kEntropy").textContent = result.entropy_bits + " bits";
    el("kPool").textContent = result.charset_size + " symbols";
    el("crackMethodText").textContent = crackMethod(result);

    // ---- requirement checklist ----
    el("checks").innerHTML = result.checks.map(c =>
      '<span class="c ' + (c.passed ? "ok" : "") + '">' +
      (c.passed ? "✓ " : "○ ") + c.label + "</span>").join("");

    // ---- weaknesses ----
    if (result.patterns.length) {
      el("findings").innerHTML = result.patterns.map(p =>
        '<div class="finding"><span class="ico">⚠</span><div>' +
        '<div class="ttl">' + p.name +
        ' <span class="pen">−' + p.penalty + "</span></div>" +
        '<div class="dsc">' + p.detail + "</div></div></div>").join("");
      el("findingsWrap").style.display = "block";
    } else {
      el("findingsWrap").style.display = "none";
    }

    // ---- suggestions ----
    if (result.suggestions.length) {
      el("tips").innerHTML =
        result.suggestions.map(s => "<li>" + s + "</li>").join("");
      el("tipsWrap").style.display = "block";
    } else {
      el("tipsWrap").style.display = "none";
    }

    // ---- breach verdict (no service/prefix details are shown) ----
    const badge = el("breachBadge");
    const text = el("breachText");
    if (!breach) {
      badge.className = "badge";
      badge.textContent = "checking";
      text.innerHTML = "Checking known breach corpora…";
      return;
    }
    if (!breach.available) {
      badge.className = "badge";
      badge.textContent = "unavailable";
      text.innerHTML = "<strong>Service unavailable.</strong> " +
        (breach.reason === "insecure-context"
          ? "Open the app over <code>http://localhost</code> or HTTPS so the " +
            "browser can hash the password locally."
          : "Could not reach the breach range API. Connect to the internet " +
            "and try again.");
      return;
    }
    if (breach.breached) {
      badge.className = "badge danger";
      badge.textContent = "breached";
      text.innerHTML = "<strong>This password has been exposed.</strong> " +
        "It appears <strong>" + breach.count.toLocaleString() +
        "</strong> time(s) in known breach corpora. Do not use it anywhere.";
    } else {
      badge.className = "badge ok";
      badge.textContent = "clean";
      text.innerHTML = "<strong>Not found in any known breach.</strong> " +
        "Checked using k-anonymity — the password itself never left " +
        "this browser.";
    }
  }

  /* -------------------------------------------------------------- events -- */
  const input = el("passwordInput");
  if (!input) return;

  let lastResult = null;
  let lastBreach = null;

  async function run() {
    const pwd = input.value;
    if (!pwd) {
      el("resultPanel").style.display = "none";
      el("breachCard").style.display = "none";
      el("findingsWrap").style.display = "none";
      el("tipsWrap").style.display = "none";
      el("emptyState").style.display = "block";
      lastResult = lastBreach = null;
      return;
    }
    lastResult = analyse(pwd);
    render(lastResult, null);
    lastBreach = await lookupBreach(pwd);
    if (input.value === pwd) {
      render(lastResult, lastBreach);
      autoSave();
    }
  }

  function autoSave() {
    if (!window.PSA_LOGGED_IN || !lastResult || !lastBreach) return;
    fetch("/api/analysis", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        score: lastResult.score,
        verdict: lastResult.verdict,
        length: lastResult.length,
        entropy_bits: lastResult.entropy_bits,
        crack_time: lastResult.crack_time,
        sha1_prefix: lastBreach.prefix,
        breached: !!lastBreach.breached,
        breach_count: lastBreach.count || 0,
        breach_source: lastBreach.source,
        pattern_count: lastResult.patterns.length,
        patterns: lastResult.patterns.map(function (p) { return p.name; })
      })
    }).then(r => r.json()).catch(() => { /* history is best effort */ });
  }

  const form = el("analyseForm");
  if (form) {
    form.addEventListener("submit", (e) => { e.preventDefault(); run(); });
  }

  const reveal = el("revealBtn");
  if (reveal) {
    reveal.addEventListener("click", () => {
      input.type = input.type === "password" ? "text" : "password";
      reveal.textContent = input.type === "password" ? "👁" : "🙈";
    });
  }

  const clear = el("clearBtn");
  if (clear) {
    clear.addEventListener("click", () => {
      input.value = "";
      el("resultPanel").style.display = "none";
      el("breachCard").style.display = "none";
      el("findingsWrap").style.display = "none";
      el("tipsWrap").style.display = "none";
      el("emptyState").style.display = "block";
      input.focus();
    });
  }
})();
