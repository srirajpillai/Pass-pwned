# Password Strength Analyser &amp; Breach Checker

> Current password validation systems rely on rigid complexity rules that fail
> to protect accounts against real-world automated cracking methodologies and
> historically compromised credentials.

A complete, end-to-end Flask application that replaces `one capital, one digit,
one symbol` style rules with **evidence based strength scoring** and a
**k-anonymity breach lookup**.

The interface is flat and content-first — white surfaces, hairline borders, one
accent colour, no blur and no decorative gradients — with a light / dark theme
toggle. It is built around three areas: a public **landing page**, the
**analyser**, and a **statistics dashboard**.

---

## 1. Features

| Area | What it does |
|---|---|
| Landing page | Public home page: what the tool does, how k-anonymity keeps the password private, and a comparison against complexity rules |
| Strength engine | Entropy based 0–100 score, verdict, character-pool size and an offline crack-time estimate |
| Attack patterns | Common-password list, dictionary words (incl. leet speak), digit/letter sequences, keyboard walks, repeated characters, years, low character variety |
| Breach check | Have I Been Pwned **range** API over k-anonymity — only 5 of the 40 SHA-1 characters are ever transmitted. No service or prefix details are shown in the UI |
| Privacy | Browser checks use local hashing; company API checks are processed transiently and only metadata is stored |
| Statistics | Score distribution, checks per day (14-day chart), most common weaknesses, average score by length, verdict mix, recent checks |
| Accounts | Register / log in / log out, per-user private history, remember-me |
| Admin | System overview, recent analyses, user enable/disable, audit trail, "All users" statistics scope |
| API | `/api/health`, `/api/range/<prefix>`, `/api/v1/analyse`, `/api/analysis` |
| UI | Flat design, sidebar shell, light + dark theme (persisted), responsive, no external assets |

---

## 2. Screens

| Route | Page |
|---|---|
| `/` | **Landing** — hero, feature grid, how k-anonymity works, comparison table, call to action |
| `/app` | **Analyser** — score, verdict, meter, requirements, crack time, weaknesses, tips and the breach verdict, updating live |
| `/dashboard` | **Statistics** — headline metrics, checks-per-day chart, score distribution, top weaknesses, average score by length, recent checks |
| `/history` | **History** — All / Breached / Weak filters, paginated, delete |
| `/admin` | **Admin** — system overview, analyses, users, audit trail |

Statistics are scoped to the signed-in user. An administrator can switch to
`?scope=all` (or press **All users**) to see the whole installation.

---

## 3. Quick start

```bash
# 1 – create a virtual environment
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 2 – install
pip install -r requirements.txt

# 3 – create the database and the admin account
python seed.py

# 4 – run
python app.py                      # http://localhost:5000
```

Default administrator

| Username | Password |
|---|---|
| `admin` | `admin123` |

> Open the app on **http://localhost:5000** (not a LAN IP). The browser's
> `crypto.subtle` API — used to hash the password locally — is only available
> in a secure context, which includes `localhost` and HTTPS.

---

## 4. Project structure

```
password_strength_analyser/
├── app.py                  # application factory + routes + JSON API
├── config.py               # configuration (env driven)
├── extensions.py           # SQLAlchemy / Flask-Login instances
├── models.py               # User, Analysis, AuditLog
├── seed.py                 # create tables + admin account
├── services/
│   ├── analyzer.py         # strength engine (pure Python, no deps)
│   ├── breach.py           # k-anonymity breach lookup + offline corpus
│   └── stats.py            # aggregations behind the dashboard
├── templates/
│   ├── base.html           # public layout (landing / login / register)
│   ├── app_base.html       # application shell (topbar + sidebar)
│   ├── landing.html
│   ├── analyser.html
│   ├── dashboard.html
│   ├── history.html
│   └── admin.html
├── static/
│   ├── css/style.css       # flat design system
│   └── js/app.js           # client engine (SHA-1, scoring, rendering)
├── tests/test_app.py       # 29 tests
├── requirements.txt
├── Procfile                # gunicorn (Heroku / Render / Railway)
├── Dockerfile
├── .env.example
└── .github/workflows/ci.yml
```

---

## 5. How the privacy model works

```
[ browser ]                                   [ this server ]        [ HIBP ]
    password
       │  SHA-1 (crypto.subtle, never sent)
       ▼
   ABCDEF0123...
   ├── prefix (5 chars) ──────────────►  /api/range/ABCDE  ────────►  range API
   │                                            │                        │
   │                                     suffix : count list ◄───────────┘
   └── suffix compared locally  ◄───────────────┘
       → breached? how many times?
```

* browser checks keep the password in the browser and send only a 5-character prefix
* company API checks send the password over HTTPS for processing, but never store it
* the database stores length, score, entropy, crack time and pattern metadata —
  **never** the password or a full hash

---

## 6. Scoring model

```
effective_length = characters left after collapsing runs ("aaaa") and
                   one-step walks ("1234", "abcd")   <- they add no search space
entropy  = effective_length × log2(size of the character pool actually used)
score    = min(100, entropy × 2.6)

then subtract penalties:
  exact match in the common-password list .............. −45  (score capped at  8)
  contains a dictionary word (leet aware) .............. −34  (score capped at 38)
  keyboard walk (qwer, asdf …) ......................... −24
  number sequence (1234, 9876 …) ....................... −22
  letter sequence (abcd …) ............................. −20
  ≥3 identical characters in a row ..................... −18
  contains a year (19xx / 20xx) ........................ −14
  shorter than 8 characters ............................ −25
  shorter than 12 characters ........................... −8
  three or more character classes missing .............. −10
```

Verdict bands — `0–20 Very Weak`, `21–40 Weak`, `41–60 Fair`, `61–80 Strong`,
`81–100 Excellent`. A password with no findings and at least 12 characters is
never scored below 82.

Crack time assumes an offline attack against a fast (unsalted) hash at
10¹⁰ guesses/second — the worst realistic case, which is why length dominates
the score.

---

## 7. HTTP API

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/health` | – | liveness probe |
| GET | `/api/range/<prefix>` | – | k-anonymity range; returns `suffix:count` pairs |
| POST | `/api/analysis` | login | stores **metadata only** |
| POST | `/api/v1/analyse` | `X-API-Key` | analyzes a password for an external system; never stores the password |

```bash
curl http://localhost:5000/api/health
curl http://localhost:5000/api/range/5BAA6

# External integration (generate a key from the logged-in Statistics page first)
curl -X POST http://localhost:5000/api/v1/analyse \
  -H "Content-Type: application/json" \
  -H "X-API-Key: psa_live_your-generated-key" \
  -d '{"password":"ExamplePassword123!"}'
```

### Using the API from a company web application

1. Create an account and log in to this application.
2. Open **Statistics** and choose **Generate API key** under Organisation
   integration. The full key is shown once, so copy it into the company's
   server-side secret manager.
3. From the company's backend, call `POST /api/v1/analyse` whenever a user
   creates or changes a password. Do not call this endpoint directly from
   browser JavaScript, because that would expose the API key.
4. Send the key in the `X-API-Key` header and the password in a JSON body.
5. Use `analysis.verdict`, `analysis.score`, `analysis.patterns`, and
   `breach.breached` to accept or reject the password in the company system.

Example backend request in JavaScript:

```js
const response = await fetch("https://password-analyser.example.com/api/v1/analyse", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-API-Key": process.env.PASSWORD_ANALYSER_API_KEY
  },
  body: JSON.stringify({ password: newPassword })
});

const result = await response.json();
if (result.analysis.score < 41 || result.breach.breached) {
  throw new Error("Choose a stronger password");
}
```

Every successful API check is recorded against the account that created the
key. That account's Statistics and History pages show the organisation's
checks. The password itself is never stored; only analysis metadata is kept.
Use HTTPS and rotate the key by generating a new one if it is exposed. A new
key immediately replaces the old key.

---

## 8. Tests

```bash
pytest -q          # 29 passed
```

Covers the strength engine (patterns, monotonicity, verdicts, crack time),
the breach service (SHA-1, prefix/suffix split, offline corpus), the statistics
aggregations, and the web layer (landing / analyser / dashboard pages, register
/ login / logout, duplicate + weak password rejection, admin authorisation,
history, and a privacy assertion that no password field is persisted and that
the breach card leaks no service or prefix details).

---

## 9. Deployment

### Vercel

1. Import `srirajpillai/Pass-pwned` into Vercel. Vercel detects the top-level
  `app.py` Flask instance automatically.
2. Add these Vercel environment variables for **Production**:
  `SECRET_KEY` (a long random value), `DATABASE_URL` (your Neon connection
  string), and optionally `HIBP_TIMEOUT` and `RANGE_CACHE_TTL`.
3. Deploy the `main` branch. The public URL will be provided by Vercel.
4. Initialise the production database once from a local shell using the same
  `DATABASE_URL` and production `SECRET_KEY`:

```bash
DATABASE_URL="postgresql://..." SECRET_KEY="..." python -m flask --app app init-db
```

Do not rely on the temporary SQLite fallback on Vercel. It is only there to
allow a demo deployment to start, and serverless local disk is not durable.
For real organisation users, API keys, and password statistics, set
`DATABASE_URL` to hosted PostgreSQL. Keep `DATABASE_URL` and `SECRET_KEY` in
Vercel's Environment Variables, never in GitHub. The app creates missing
tables on startup; existing databases are upgraded with the API-key columns.

If Vercel still shows `FUNCTION_INVOCATION_FAILED`, open **Vercel → Project →
Logs** and check that `DATABASE_URL` is present under the **Production** scope,
the URL starts with `postgresql://` or `postgres://`, and the database allows
connections from external services. Redeploy after changing an environment
variable.

### Recommended database: Neon PostgreSQL

Use Neon for the deployed database. It is PostgreSQL, so it works with the
application without changing the data models.

1. Open [neon.tech](https://neon.tech) and create an account.
2. Create a project named `password-analyser`.
3. Choose the default PostgreSQL database and copy the connection string. It
  should look similar to:

```text
postgresql://user:password@ep-example.region.aws.neon.tech/neondb?sslmode=require
```

4. In Vercel, open **Project Settings → Environment Variables**.
5. Add `DATABASE_URL` with the Neon connection string and select **Production**.
6. Add `SECRET_KEY` with a long random value and select **Production**.
7. Save the variables and redeploy the latest `main` commit.

The application creates its tables automatically when the Vercel function
starts. After deployment, open `/register`, create the first company account,
open **Statistics**, and generate an organisation API key. Do not commit the
Neon connection string or `SECRET_KEY` to GitHub.

**Docker**

```bash
docker build -t password-analyser .
docker run -p 5000:5000 -e SECRET_KEY=... password-analyser
```

**Heroku / Render / Railway** — the included `Procfile` runs gunicorn:

```
web: gunicorn "app:create_app()" --bind 0.0.0.0:$PORT --workers 2 --timeout 60
```

Set `SECRET_KEY` (required) and, for production, `DATABASE_URL` pointing at
PostgreSQL instead of the bundled SQLite file.

---

## 10. Notes & limitations

* The bundled common-password list is small and dependency free. For production
  use, load a larger corpus (or `zxcvbn`) into `services/analyzer.py`.
* If the machine has no internet access the breach service falls back to a tiny
  offline corpus of well-known breached passwords so the feature remains
  demonstrable; the UI labels such results accordingly.
* Range responses are cached in-process for 15 minutes (`RANGE_CACHE_TTL`).

---

## 11. Credits

* Strength model follows the reasoning in NIST SP 800-63B — length and
  screening against known-bad passwords matter more than composition rules.
* Breach data: [Have I Been Pwned — Pwned Passwords](https://haveibeenpwned.com/Passwords)
  (k-anonymity range API).
