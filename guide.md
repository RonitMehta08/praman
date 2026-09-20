# PRAMAN — Frontend Guide

**A plain-English tour of every screen, tab, button, table, chart and message in the PRAMAN web interface.**

This guide assumes you know nothing about the project. Read section 1 to get it running, section 4 to upload your first test case, and then dip into whichever screen you are looking at.

---

## Contents

1. [Starting the app](#1-starting-the-app)
2. [What PRAMAN actually does](#2-what-praman-actually-does)
3. [Words you will see everywhere](#3-words-you-will-see-everywhere)
4. [How to upload a test case](#4-how-to-upload-a-test-case)
5. [The parts of the screen that never change](#5-the-parts-of-the-screen-that-never-change)
6. [The eight tabs, one by one](#6-the-eight-tabs-one-by-one)
   - [6.1 Overview](#61-overview)
   - [6.2 Upload](#62-upload)
   - [6.3 Simulate](#63-simulate)
   - [6.4 Devices](#64-devices)
   - [6.5 Findings](#65-findings)
   - [6.6 Training](#66-training)
   - [6.7 Topology](#67-topology)
   - [6.8 Ledger](#68-ledger)
7. [The two hidden screens](#7-the-two-hidden-screens)
   - [7.1 One device](#71-one-device)
   - [7.2 Remediation plan](#72-remediation-plan)
8. [Three shared pieces, explained once](#8-three-shared-pieces-explained-once)
   - [8.1 The findings table](#81-the-findings-table)
   - [8.2 The configuration viewer](#82-the-configuration-viewer)
   - [8.3 The charts](#83-the-charts)
9. [Reading the colours](#9-reading-the-colours)
10. [Your first ten minutes — a full walkthrough](#10-your-first-ten-minutes--a-full-walkthrough)
11. [When something looks wrong](#11-when-something-looks-wrong)
12. [Cheat sheet](#12-cheat-sheet)

---

## 1. Starting the app

You only do the install once.

### Step 1 — install (once)

```bash
cd praman && python -m venv .venv && .venv/Scripts/python.exe -m pip install -r requirements.lock.txt
```

On Linux or macOS, use `.venv/bin/python` everywhere instead of `.venv/Scripts/python.exe`.

You need **Python 3.10 or newer**. Nothing else — no Docker, no Node.js, no database server, no internet connection after the install.

### Step 2 — create your account (once)

There is no default account and no way to create one through the web interface —
running this script is what proves you have access to the machine, which is a
stronger check than any open HTTP page could be.

```bash
.venv/Scripts/python.exe scripts/manage_users.py add --username you --role approver
```

It asks for a passphrase twice and never accepts one on the command line, because
`argv` ends up in your shell history. Minimum 12 characters. `approver` is the
role that can do everything; see [The three roles](#the-three-roles) below.

Skip this and the app still starts — you just get a sign-in box that tells you to
come back and run it.

### Step 3 — start the server

```bash
.venv/Scripts/python.exe scripts/serve.py
```

### Step 4 — open the interface

Open <http://127.0.0.1:8012> in your browser and sign in with the account you
just made.

That is it. The web interface and the API are the **same program on the same port** — there is no separate frontend server to start, no `npm install`, no build step.

### If port 8012 is busy

You can pick another port with an environment variable:

```bash
PORT=9000 .venv/Scripts/python.exe scripts/serve.py
```

Then open `http://127.0.0.1:9000`.

There is also a second, more manual way to start the same app, which you will see quoted in the app's own error messages:

```bash
.venv/Scripts/python.exe -m uvicorn backend.app.main:app --port 8000
```

That one opens on <http://127.0.0.1:8000> instead. Both commands run the identical application — `scripts/serve.py` just defaults to 8012 and reads `PORT`/`HOST` from the environment for you.

### Two things that will trip you up

| Mistake | What happens | Fix |
|---|---|---|
| Double-clicking `frontend/index.html` | You get a stuck "Starting the interface…" message. Browsers block JavaScript modules loaded from `file://`. | Start the server and use `http://127.0.0.1:8012`. |
| Binding `HOST=0.0.0.0` | It works, and every route still asks for a login — but the API speaks plain HTTP, so your session token and every finding cross the network in clear text. | Leave the default; it binds loopback only, on purpose. If you genuinely need it on a network, put `deploy/nginx/praman.conf` in front of it first. See `docs/SECURITY.md` §2. |
| Expecting to log in on a fresh clone | There is no default account, so `/auth/login` answers 503 and tells you what to run. | `.venv/Scripts/python.exe scripts/manage_users.py add --username you --role approver` |

> **Security note, stated plainly:** every route except `/health`, `POST /auth/login` and the static frontend requires a signed-in operator, and the account you sign in as is written *inside* the signed audit record. What this build still does **not** have is TLS: the application does not implement it and will not, so on anything but loopback it belongs behind a reverse proxy. That, not the missing login, is now the reason the default only listens to your own machine.

### The three roles

You pick one when you create an account, and it decides what the UI lets you do.

| Role | May |
|---|---|
| `viewer` | Read everything — devices, findings, reports, the ledger, the training queue |
| `auditor` | Everything a viewer may, plus upload configurations and run simulations |
| `approver` | Everything an auditor may, plus **commit audits to the ledger** and **teach parser mappings** |

They are ordered, so there is no role that can commit an audit but not read one. A greyed-out button in the UI is a courtesy — the route answers 403 either way, and the topbar shows which account you are on so a disabled Commit button explains itself.

### The AI part is optional

PRAMAN works perfectly with **no AI models installed at all**. The compliance verdicts are produced by fixed, deterministic rules — no model is ever involved in deciding pass or fail. The AI only helps *suggest* what an unrecognised configuration line might mean.

When an AI tier is missing, the interface says so on screen rather than pretending. If you want to install the tiers, the download commands live in `../MANUAL_COMMANDS.md` — they are deliberately not automatic, because they pull about **2.4 GB** and want a GPU.

---

## 2. What PRAMAN actually does

You give it a router or switch **configuration file** — the text you get from `show running-config`. It gives you back:

1. **A verdict per rule** — does this device satisfy each control in CIS, DISA STIG, NIST SP 800-53 and ISO 27001?
2. **Evidence** — the exact file and line number that produced each verdict.
3. **A fix** — the remediation command line, copied from what the benchmark publisher themselves wrote.
4. **A signed record** — a PDF and a tamper-evident ledger entry, so the report can be re-checked later without trusting the program that made it.

All of it runs offline on one laptop.

---

## 3. Words you will see everywhere

Learn these six and the whole interface becomes readable.

| Word | Plain meaning |
|---|---|
| **Device** | One configuration file you uploaded. PRAMAN calls it a device even though it never talked to real hardware. |
| **Fact** | One setting pulled out of the config, stored in a standard form. `line vty 0 4 / transport input ssh` becomes a fact at a path like `line.vty.transport_input`. There are **330 possible paths**, and every vendor gets translated into the same 330, which is why one rule works across vendors. |
| **Control** | One requirement from a published standard. Example: CIS 1.1.1 "Enable `aaa new-model`". |
| **Finding** | The result of checking one control against one device. A finding carries a verdict, a severity, evidence and references. |
| **Framework** | The standard the control came from — CIS, DISA STIG, NIST SP 800-53, or ISO 27001. |
| **Commit** | The deliberate act of turning a device's current results into a permanent, signed, chained record. **Uploading is not committing.** |

### The single most important idea in the whole interface

A finding can have **nine** different results, but only **two** of them are verdicts.

| Result | What it means | Is it a verdict? |
|---|---|---|
| `pass` | The device satisfies the control. | ✅ Yes |
| `fail` | The device violates the control. | ✅ Yes |
| `error` | The check itself broke. | ❌ No |
| `unknown` | The config genuinely cannot answer this. | ❌ No |
| `fixed` | Was failing, has been remediated. | ❌ No |
| `notapplicable` | This control does not apply to this device. | ❌ No |
| `notchecked` | **PRAMAN has no automated rule for this control.** | ❌ No |
| `notselected` | Not part of the selected scope. | ❌ No |
| `informational` | Context, not a requirement. | ❌ No |

**`notchecked` is never shown as a pass.** This matters enormously. PRAMAN automates 454 controls out of 3,366 loaded controls. The other 2,912 come back as `notchecked` with a reason attached — reported, not quietly dropped. A tool that dropped them would show you a beautiful score built on 13% coverage.

That is also why the score formula excludes them:

```
score = pass / (pass + fail)
```

`notchecked`, `notapplicable` and `unknown` are left out entirely. You **cannot** improve a PRAMAN score by failing to check something.

Everywhere you see a score, look for the coverage number next to it. The two are meant to be read together.

---

## 4. How to upload a test case

This is the section you will use most, so it comes early.

### You do not need a real device

**Ten ready-made configuration files ship inside the project**, under `test_configs/`. Use these as your test cases.

| File | What it is | CIS score | DISA STIG score |
|---|---|--:|--:|
| `compliance_extremes/fully_hardened.conf` | Everything done right | 100.0% | 96.9% |
| `compliance_extremes/fully_noncompliant.conf` | Everything done wrong | 0.0% | 0.0% |
| `realistic/secure_baseline.conf` | A well-run device | 74.6% | 27.6% |
| `realistic/enterprise_complex.conf` | Big, messy, mostly good | 79.0% | 37.9% |
| `realistic/partial_compliance.conf` | Half-hardened | 41.8% | 20.7% |
| `realistic/telnet_exposed.conf` | SSH added, telnet never removed | 17.2% | 13.8% |
| `realistic/insecure_minimal.conf` | Small and bad | 10.3% | 6.9% |
| `device_identity/router_with_show_version.conf` | Config **plus** `show version` output | 67.2% | 20.7% |
| `device_identity/stacked_switch_with_inventory.conf` | A 4-member switch stack with inventory | 52.8% | 17.2% |
| `feature_coverage/crypto_ipsec_isis.conf` | IPsec / IKEv2 / IS-IS settings | 34.0% | 23.3% |

**Which one should you pick first?** Use `realistic/telnet_exposed.conf`. It is small, it fails in obvious ways you can recognise by eye, and it produces a proper mix of pass and fail rather than a flat 0% or 100%.

> Why are the DISA STIG scores so much lower? That is expected, not a bug. A Network Device Management STIG asks for things a CIS-hardened config has no reason to carry — a DoD trust point, a common-criteria password policy, FIPS-approved SSH algorithm lists. The **pair** of numbers is the useful output. A tool that showed you only the friendlier number would be the problem.

### Method 1 — upload one file (the normal way)

1. Click the **Upload** tab.
2. You will see a large dashed box that says **"Drop configuration files here"**.
3. Click anywhere inside the box, or click the **Choose files** button.
4. Navigate to `praman/test_configs/realistic/` and pick `telnet_exposed.conf`.
5. Watch the **Ingest results** table appear underneath.
6. Click **Review 1 ingested device(s)** to jump to the Devices tab.

You can also just **drag the file from your file manager and drop it onto the box**. The box's border lights up while you are dragging over it.

The box is also keyboard-reachable: `Tab` to it, then press `Enter` or `Space` to open the file picker.

### Method 2 — upload several files at once

Same as above, but select multiple files in the picker (`Ctrl`-click or `Shift`-click), or drag several at once.

PRAMAN uploads them **two at a time**. A progress bar appears reading `3 of 10 uploaded`, and each file gets its own row in the results table with its own status.

**A failure on one file does not stop the others.** If you upload 40 files and two of them are Word documents, you get 38 devices and two rows explaining what went wrong with the other two.

### Method 3 — upload a whole folder

1. Click the **Choose a folder** button (the quieter button next to "Choose files").
2. Pick `praman/test_configs/`.
3. Your browser will ask permission to upload the folder's contents — say yes.
4. All ten fixtures go in, one row each.

This uses a browser feature (`webkitdirectory`). If your browser does not support it, you silently get an ordinary multi-file picker instead — no error.

### Method 4 — upload a ZIP of an entire estate

If you have hundreds of configs, zip them and drop the single `.zip` file on the box. This takes a different, faster path on the server that expands the archive in one request.

**Rules for the ZIP path:**

- **Exactly one ZIP, on its own.** If you drop a ZIP *together with* loose files, PRAMAN refuses the whole thing and shows you a message explaining why: the bulk route needs a single archive so it can enforce its limits across the whole thing.
- Server-enforced ceilings:

  | Limit | Value |
  |---|---|
  | Upload size (the compressed `.zip`) | 64 MB |
  | Files inside the archive | 2,000 |
  | One config, uncompressed | 8 MB |
  | Whole archive, uncompressed | 512 MB |

- Paths with `..` in them are rejected outright.

These limits are the **zip-bomb guard**. If your archive gets refused for one of them, the system is working as designed. A 400-device estate at roughly 40 KB per config comes to under 20 MB, so the limits are generous for real work.

### Method 5 — try a config without storing anything

Use the **Simulate** tab instead. Paste config text, click **Check**, get full results — and **nothing** is saved. No device row, no ledger record, nothing to clean up afterwards. See [section 6.3](#63-simulate).

This is the right choice when you want to test a production config but do not want it in the database.

### Method 6 — upload from the command line

With the server running:

```bash
curl -F "file=@test_configs/realistic/telnet_exposed.conf" http://127.0.0.1:8012/ingest
```

### What happens to your file, in order

The Upload screen prints these four steps on the page itself. They matter:

1. **Secrets are redacted before anything is stored.** A password in your config never reaches the database or a report. What you see later in the configuration viewer is the redacted text, not the real value.
2. **The vendor is detected**, the matching pattern pack parses the text into canonical facts, and **every fact records where it came from** — source file, line span, which parser produced it, and a confidence number.
3. **Lines no pattern recognises are counted and queued** for the Training module. They are never silently dropped.
4. **Nothing is written to the ledger yet.** Ingest is not an audit. You commit an audit explicitly, later, by choice.

### What your file needs to look like

Plain text, UTF-8 (a byte-order mark is fine). A `show running-config` dump. Anything from a vendor with a pattern pack — check the **"Vendors currently recognised"** panel at the bottom of the Upload screen to see which are loaded right now.

**A vendor that is not on that list is not a dead end.** Upload the config anyway. It will parse whatever it can, and every line it could not understand lands in the Training queue where you can teach it — see [section 6.6](#66-training). That takes effect immediately, with no restart.

---

## 5. The parts of the screen that never change

Everything below is present on every screen.

### While the app is loading

Before the JavaScript finishes, you see:

```
◈ PRAMAN
Starting the interface…
```

If that message is still there after **4 seconds**, it rewrites itself into a warning telling you the most likely cause — that you opened the file directly instead of through the server — and gives you the command to start the server properly.

If you have JavaScript switched off entirely, you get a short block explaining that the API still works without the interface, and pointing you at `/docs` (the interactive API documentation) and `/devices/{device_id}/report.pdf`.

### The sign-in box

The next thing you see is a dark overlay with two fields — **Operator name** and **Password** — and one line explaining why it is asking: *"Every audit committed to the ledger is signed with the name you use here."* Nothing behind it loads until you get past it, deliberately: a signed-out session that rendered the dashboard first would fire a dozen requests the server is bound to refuse, and you would read a dozen errors instead of a password field.

Three things it says that are worth reading rather than clicking past:

- **"Checking. Key derivation takes about a fifth of a second."** appears while it works. That pause is the password hashing (600,000 PBKDF2 iterations) and it is intentional.
- **"invalid credentials"** is all you get on a bad attempt — it does not tell you whether the name or the password was wrong, because an answer that distinguished them would hand out a list of valid operator names.
- **"There is no default account…"** at the bottom, with the command. If you skipped [Step 2](#step-2--create-your-account-once), this is where you find out.

After ten failed attempts the server stops answering for fifteen minutes and the box tells you how many seconds are left.

If the box reappears mid-session it says why — twelve hours elapsed, or an administrator changed your password or disabled the account. Your session token lives in `sessionStorage`, so it survives a page reload but **not** closing the tab. That is on purpose: a token that outlived the browser would mean the next person to open PRAMAN on a shared assessment laptop inherits your identity, and the ledger would sign their work with your name.

If the backend is not running you get the shell and the footer error instead of the sign-in box — a password field in front of a dead server cannot succeed, and it would hide the message telling you how to start it.

### The top bar

Reading left to right:

| Element | What it is |
|---|---|
| **◈ PRAMAN** | The product name. Click it to go back to Overview. |
| *Network configuration compliance auditor* | A one-line description. |
| **`offline`** badge | A permanent reminder that this app makes no outbound network calls. It is not a connection status — it never changes. |
| **Nav tabs** | Overview · Upload · Simulate · Devices · Findings · Training · Topology · Ledger. The current tab is highlighted. |
| **Your name and role** | Who this browser tab is signed in as, with the role beside it — `viewer`, `auditor` or `approver`. It is on screen at all times on purpose: a greyed-out **Commit audit** button reads as a broken build until you notice the word `viewer` next to it. |
| **Sign out** | Revokes the session **on the server**, not just in this browser, then puts the sign-in box back. If the server does not confirm the revocation it says so rather than pretending. |
| **◐** button | Switches between light and dark mode. Hovering shows "Switch between light and dark". |

Your theme choice is remembered in your browser (`localStorage`, key `praman.theme`). If you have never chosen, PRAMAN follows your operating system's light/dark setting. The switch is applied **before the page paints**, so you never get a white flash on a dark desktop.

Switching the theme also **redraws every chart**, because chart colours differ between light and dark surfaces.

### The skip link

Press `Tab` as the very first thing on any page and a **"Skip to content"** button appears. Activating it jumps your keyboard focus past the navigation straight into the main content. It is invisible until focused. This is a screen-reader and keyboard-user convenience.

### The main area

Everything between the top bar and the footer. Each screen renders here.

Every screen has the same shape:

- A **title** (e.g. "Overview")
- A **subtitle** explaining the screen in one line
- Sometimes **action buttons** on the right of the title
- Then a stack of **panels** — bordered boxes, each with a heading

### The footer

Stamped with live information from the server: the app name, version, and the problem statement it was built for. Plus this line, which is a statement of design intent:

> No telemetry. No outbound network calls. Verdicts are deterministic — no model is in the decision path.

If the footer instead shows a `uvicorn` command, the interface could not reach the server. See [section 11](#11-when-something-looks-wrong).

### Toasts (the little pop-up messages)

Small notifications slide in at the corner.

| Kind | Colour | Behaviour |
|---|---|---|
| success | green | Disappears after about 4 seconds |
| info | blue | Disappears after about 4 seconds |
| warn | amber | Disappears after about 4 seconds |
| **error** | red | **Stays until you dismiss it** |

Errors persist on purpose — an error that vanishes before you read it is an error you will hit again. Most toasts have a bold headline and a smaller detail line underneath with the specific reason.

### The address bar is part of the interface

PRAMAN uses **hash routing**. The bit after the `#` is the screen you are on:

```
http://127.0.0.1:8012/#/devices
http://127.0.0.1:8012/#/device/edge-rtr-01
http://127.0.0.1:8012/#/device/edge-rtr-01?line=42
http://127.0.0.1:8012/#/findings?result=fail&severity=high
http://127.0.0.1:8012/#/simulate?sample=Insecure%20router
```

Which means:

- **Every screen is bookmarkable and shareable.** Copy the URL, send it to a colleague, they land on exactly what you were looking at — including your filters.
- **Browser Back and Forward work normally.**
- Reloading the page keeps you where you were.

> Why a `#`? Because the server deliberately has no catch-all route. If it returned the interface for every unknown URL, an API typo would come back as a silent `200 OK` full of HTML instead of a clear `404`. The `#` keeps routing entirely in the browser and lets the server stay strict.

### Spinners and empty states

While a screen fetches data you get a spinner with a sentence saying what it is doing, e.g. *"Parsing, evaluating rules, and classifying unknown lines…"*.

When there is genuinely nothing to show, you get an **empty state**: a short explanation plus a hint about what to do next — not a blank box.

---

## 6. The eight tabs, one by one

### 6.1 Overview

**The whole estate at a glance.** This is your home screen.

**Title buttons:** **Upload configs** · **Verify ledger**

#### The six tiles

| Tile | The big number | The small hint underneath |
|---|---|---|
| **Devices ingested** | How many configs you have uploaded | How many distinct vendors, or "Upload a config to begin" |
| **Committed audits** | How many signed ledger records exist | The latest sequence number, or "Nothing signed yet" |
| **Estate pass rate** | `pass / (pass + fail)` across every committed audit | `71 pass / 19 fail over 90 decided`, or "No verdict has been committed yet" |
| **Ledger integrity** | `verified`, `N broken`, or `unknown` | How many records checked out, or an instruction to open the Ledger tab |
| **Controls loaded** | Total controls known to the engine | How many automated checks across how many catalogs |
| **Automation coverage** | The share of loaded controls a rule can actually decide | "Share of loaded controls a deterministic rule can decide" |

Hover **Estate pass rate** and a tooltip reminds you it is *"a PRAMAN ratio, not a published metric"*. Hover **Automation coverage** and it tells you everything outside that share is reported as `notchecked`, never as `pass`.

**Important:** the Estate pass rate is summed from the **ledger** — from what you actually committed and signed — not from re-checking every device. If you have uploaded ten devices and committed none, this tile reads `—`. That is correct behaviour, not a bug.

#### AI escalation ladder

A four-row list showing which AI tiers are installed on this machine. Each row has a coloured dot, a name, a state, and a note.

| Tier | Note on screen | What it is |
|---|---|---|
| **Tier 0 — deterministic patterns** | "Always on; the only tier in the verdict path" | Fixed pattern matching. Always available. |
| **Tier 1 — TF-IDF char n-gram** | τ = 0.85 | A small statistical text classifier. |
| **Tier 2 — SetFit** | τ = 0.80 | A small sentence-embedding classifier. |
| **Tier 3 — local Qwen3-4B** | τ = 0.70, grammar-constrained | A local language model. |

**τ (tau) is a confidence threshold.** If a tier cannot beat its threshold, the line escalates to the next tier. If no tier can, the line **abstains** — it goes to the Training queue for a human instead of getting a guessed answer. A wrong mapping produces a confidently wrong fact, which is worse than no answer.

Tiers 1 and 2 read simply `loaded` or `not loaded` — a file either exists or it does not. **Tier 3 is different**, because it is a running server, and its state can be a few seconds stale. It shows one of:

- `reachable · checked 3s ago`
- `not reachable · checked 28s ago` — the model is on disk but the server is not running (start it: MANUAL_COMMANDS.md Step 6)
- `no weights on disk` — you have not downloaded the 2.4 GB model yet

Those last two are deliberately different messages, because they are two different jobs. A single "not loaded" badge would send someone who already finished the download back to the download.

Under the list, two notes worth reading:

> The ladder classifies unrecognised configuration lines so an admin can map them. It never issues a verdict — compliance results come only from deterministic rules, so a tier being unavailable narrows what PRAMAN can suggest and cannot change what it concludes.

And the active backend name, plus the reminder that below-threshold lines abstain.

#### The charts

Up to four, and each only appears when it has real data:

1. **Framework stacked bars** — pass/fail split per framework, taken from your most recently audited device.
2. **Result distribution** — how the nine result values are spread for that device.
3. **Severity bars** — high/medium/low, counting **failures only**.
4. **Trend line** — score over successive commits.

Two honest touches here:

- The severity chart counts **failing** findings only. An earlier version charted all findings and reported "16,082 failing controls" on an estate that had 372 failures.
- With exactly **one** committed audit, you get no trend chart. Instead a small panel says so and tells you a second commit will start the line. A chart of one point would only restate the number above it.

#### Recent commits

The last 8 ledger entries, newest first.

| Column | Meaning |
|---|---|
| **Seq** | Position in the chain (`#1`, `#2`, …) |
| **Device** | Hostname |
| **Score** | `pass / (pass + fail)` for that record |
| **Fail** | Count of failures |
| **Committed** | When |
| **Record hash** | A shortened fingerprint |

#### Loaded runtime

What is loaded in the engine right now: Pattern library version, Pattern packs, Vendors recognised, Rule pack version, Rules loaded, Catalogs loaded, Controls total.

The note explains why this panel exists:

> These counters move when a pattern pack is dropped in or a mapping is taught, which is how a hot reload is observable rather than a claim.

Teach a mapping in the Training tab, come back here, and the numbers will have moved. That is the "no redeploy" claim being demonstrated rather than asserted.

#### If you have no devices yet

You get an empty state telling you to upload a configuration or drop a ZIP, and pointing out that sample configs ship under `test_configs/`.

---

### 6.2 Upload

**Getting configuration files into PRAMAN.**

*Subtitle: "Unified ingestion — single file, folder, or ZIP archive (C1)"*

Fully covered in [section 4](#4-how-to-upload-a-test-case). Here is the element inventory.

#### The drop zone

A large dashed box containing:

- **"Drop configuration files here"** (the title)
- **"One file, a whole folder, or a single .zip of an estate. Any supported vendor, mixed freely."** (the hint)
- **Choose files** button — opens a multi-file picker
- **Choose a folder** button — opens a folder picker

The whole box is clickable, dragged-onto-able, and keyboard-focusable (`Enter` or `Space` opens the picker). Its border highlights while a drag hovers over it.

#### The progress bar

Only appears during a multi-file upload, and disappears when finished. Reads `4 of 10 uploaded`. It is a proper accessible progress bar, so a screen reader announces the count.

#### Ingest results

The panel heading itself is a summary: **"Ingest results — 8 ok, 2 failed"** (and `, 3 pending` while still running).

| Column | Meaning |
|---|---|
| **File** | The filename you uploaded |
| **Status** | A green `ok` pill, a red `failed` pill, or `pending` / `running` |
| **Hostname** | The device identity PRAMAN worked out |
| **Vendor** | The vendor it detected |
| **Facts** | How many settings it extracted |
| **Unrecognised lines** | How many lines it could not parse |
| **Detail** | e.g. `3 template(s) queued for training`, or the rejection reason |

Caption: *"One row per file. A failure here does not affect the others."*

**Follow-up buttons appear underneath when relevant:**

- **Review N ingested device(s)** → jumps to the Devices tab
- **Teach the unrecognised lines** → jumps to the Training tab. Only shown when at least one file actually produced unrecognised lines.

**If any file failed**, a note appears:

> A failed file was rejected before anything was stored — no partial device was created. The usual causes are a non-configuration file, a vendor with no pattern pack yet, or a size limit.

#### What happens to an uploaded file

The four-step list described in [section 4](#what-happens-to-your-file-in-order). Read it once.

#### Vendors currently recognised

A row of chips, one per loaded pattern pack. Plus two notes: that an unlisted vendor is not a dead end (upload it, then teach it in Training, effective immediately with no redeploy), and that the size limits are enforced server-side and reported per file.

#### Behaviour you should know about

- **Only one upload runs at a time.** Start a second while one is running and you get a "An upload is already running." warning.
- **A ZIP mixed with loose files is refused entirely** with an explanation.
- Loose files go up **two at a time**.

---

### 6.3 Simulate

**Paste a config, see results, store nothing.**

*Subtitle: "Paste a configuration and see the verdicts — nothing is stored"*

This is the screen to use when you want to check something without it ending up in your database. The endpoint behind it is stateless and idempotent: **no device row, no ledger record, nothing to clean up.** Secrets are still redacted server-side before parsing.

That property is printed on the screen, not buried in documentation, because an auditor pasting a production config into a tool needs to know **before** they paste.

**Title buttons:** **Check** (run it) · **Clear** (empty the editor and wipe the results)

#### The toolbar

| Element | What it does |
|---|---|
| **Recorded as** text field | The filename that appears in the evidence trail. Defaults to `inline.conf`. Leave it or change it — it is cosmetic, but it is what you will see cited under each finding. |
| **Load a sample** buttons | Three built-in configs, described below. |

#### The three samples

| Button | What it contains | What it demonstrates |
|---|---|---|
| **Insecure router** | `enable password cisco123`, `no service password-encryption`, `no aaa new-model`, `ip http server`, `exec-timeout 0 0`, `transport input telnet`, `snmp-server community public RO`, `no logging on` | A wall of failures with obvious causes |
| **Hardened router** | `service password-encryption`, `enable secret 5 …`, full `aaa` stack, `no ip http server`, `login block-for`, a MOTD banner, `exec-timeout 5 0`, `transport input ssh`, `ip ssh version 2`, logging to a host, `ntp authenticate` | Mostly passes |
| **Unknown vendor lines** | Juniper-style `set system services ssh …` plus invented lines like `proprietary-hardening-profile level strict` | **The AI classifier and the Training queue.** This is the one to click if you want to see how PRAMAN handles syntax it has never met. |

Clicking a sample fills the editor, renames the "Recorded as" field to match (e.g. `insecure-router.conf`), clears any old results, and toasts *"Click Check to run it."*

You can also deep-link to a loaded sample: `#/simulate?sample=Insecure router`.

#### The editor

A 16-row monospace text area. Spell-check is off. Placeholder: *"Paste a device configuration here, or load one of the samples below."*

Underneath it, two notes: the stateless guarantee quoted above, and a live count — *"103 deterministic rules across 42 catalogs are available. Only rules whose catalog matches the detected vendor and OS will be applied."*

Click **Check** with an empty editor and you get a warning toast, not a crash.

#### What you get back

**Panel: Result**

- The **detected hostname** in large text, or `(no hostname in this config)`
- A line reading *"Detected as cisco / ios 15.2. Nothing was stored — this run wrote no device row and no ledger record."*
- **Ingest this config for real** button — takes exactly what you pasted, uploads it properly, and jumps you to that device's page. Use this when the simulation looks right and you now want it on the record.
- **Four charts:** compliance gauge, result distribution, severity bars, framework stacked bars

**Panel: Coverage of the standard**

A seven-row table that is the honesty check on the score above it:

| Row |
|---|
| Catalogs selected for this device |
| Catalogs skipped (different vendor or OS) |
| Controls in the selected catalogs |
| Controls a rule can decide automatically |
| Rules loaded |
| Rules inapplicable to this device |
| Automation coverage |

With the note: *"The score above is computed over the controls a rule could decide. Everything else is reported as notchecked, never as a pass — so these two numbers have to be read together."*

**Panel: Findings (N)**

The full findings table — see [section 8.1](#81-the-findings-table). It opens **pre-filtered to failures**, because that is what you came for. Clear the filter to see everything.

**Panel: Configuration**

Your config, rendered with line numbers and coloured markers showing which lines caused which verdicts — see [section 8.2](#82-the-configuration-viewer). Clicking a line number inside a finding's evidence scrolls this viewer to that line and flashes it.

If some findings have no line to point at, a note tells you: *"N finding(s) cite a setting that is absent from this configuration, so they have no line to point at. Their verdict rests on the absence itself."* That is a real and common case — "you never configured logging" has no line number.

**Panel: Unrecognised lines (N)**

If everything parsed: *"Every line was matched by a deterministic pattern."*

Otherwise, a table of what the AI proposed for each line:

| Column | Meaning |
|---|---|
| **Line** | Line number |
| **Text** | The actual line |
| **Proposed path** | The canonical path the classifier suggests — or an `abstained` pill |
| **Tier** | Which tier answered: `Tier 0 · pattern`, `Tier 1 · TF-IDF`, `Tier 2 · SetFit`, `Tier 3 · LLM`, or `none` |
| **Confidence** | A number from 0.00 to 1.00 |
| **Block** | Which config block the line sat in |

Plus a note that these proposals are **suggestions for an admin to approve, never verdicts**, and if any lines abstained:

> N line(s) abstained — no tier was confident enough to propose a path. That is the designed outcome, not a failure: a wrong mapping produces a confidently wrong fact.

And an **Open the training queue** button.

**Panel: AI tier status for this run**

Four chips, one per tier, each reading either `available` or `not installed`. The word is printed, not just the colour, so the state is readable without relying on colour vision. Below them, the backend name and any note.

`not installed` here is **a supported state, not a fault**.

---

### 6.4 Devices

**The list of everything you have uploaded.**

*Subtitle: the count, e.g. "5 ingested"*

**Title button:** **Upload more**

**Controls at the top:**

| Control | What it does |
|---|---|
| **Filter field** | Type to narrow the list. Placeholder: *"hostname, vendor, or source file"* |
| **Sort buttons** | `ingested` · `hostname` · `vendor` · `facts` · `latest audit`. Click one to sort by it; click the same one again to reverse. The active button shows ↓ or ↑. |

#### The table

| Column | Meaning |
|---|---|
| **Hostname** | A clickable link — opens that device's full report. Reads `(no hostname)` if the config had none. |
| **Vendor** | Detected vendor, plus the OS family after a slash |
| **OS version** | Detected version, or `—` |
| **Facts** | How many settings were extracted |
| **Latest audit** | A green **`seq #3`** pill if it has been committed, or a grey **`not committed`** pill if not |
| **Ingested** | When you uploaded it |
| *(actions)* | **PDF** and **Re-commit** / **Commit audit** |

The caption under the table reads `5 of 5 devices.` — so when you filter, you can always see how much you have hidden. Filter to something that matches nothing and you get *"No device matches that search."*

#### The two actions

- **PDF** — only appears once the device has a committed audit. Downloads the signed report as `<hostname>.pdf`.
- **Commit audit** (first time) or **Re-commit** (after that) — evaluates the stored facts against the **current** rules and appends a signed, hash-chained record to the ledger. The tooltips say exactly that: *"Write the first immutable audit record for this device"* / *"Evaluate the stored facts against the current rules and append a new ledger record."* While it runs the button reads **Committing…**.

#### The note that explains the whole model

When any device has facts but no audit, a note appears with the count:

> 3 device(s) have facts stored but no committed audit. Ingesting is not auditing — until you commit, there is no signed record and no PDF.

This is the single most common point of confusion. Uploading a file gets you *facts*. Committing gets you a *record*. They are separate on purpose: you can upload freely and experiment, and only the commits you deliberately make become permanent, signed history.

#### If you have no devices at all

An empty state pointing you at the Upload view, at `test_configs/`, and at the three inline Simulate samples you can run without storing anything.

---

### 6.5 Findings

**Every failing control, across every device, in one place.**

Use Devices when you are asking *"how is this router doing?"*. Use Findings when you are asking *"what is wrong across my whole estate, and how widespread is it?"*

This screen has to fetch each device individually and combine them in your browser, because there is no single estate-wide endpoint. It tells you how many requests it made, so a slow load has a visible cause rather than feeling broken.

#### The four tiles

| Tile | Meaning |
|---|---|
| **Devices aggregated** | How many devices went into this view |
| **Distinct controls failing** | How many different controls fail *somewhere* |
| **Failing everywhere** | How many controls fail on **every single device**. Look here first — see below. |
| **Estate pass rate** | The combined ratio |

#### Severity chips

A quick count of failures by severity: high, medium, low.

#### Failing controls across the estate

| Column | Meaning |
|---|---|
| **Control** | The control id |
| **Framework** | Which standard |
| **Severity** | high / medium / low |
| **Title** | What the control requires |
| **Devices failing** | How many devices fail it |
| **Also passing on** | How many devices *pass* it — the contrast column |
| **Affected** | Up to six clickable device names, then `+N more` |

Click any device name and you land on that device's report, already filtered to its failures.

**The "Also passing on" column is the useful one.** A control failing on 40 devices and passing on 0 is probably a policy nobody rolled out. A control failing on 40 and passing on 3 means somebody knows how to fix it — go ask them.

#### The universal-failure warning

When a control fails on **every** device, a warning appears. That pattern usually means one of two things, and they need opposite responses:

- an estate-wide misconfiguration you should genuinely fix, **or**
- a rule that no configuration can satisfy, which is a bug in the rule pack

Either way it deserves a human look before you file 40 tickets.

#### Estate shape

Charts summarising the distribution across the estate.

#### Drill into one device

A dropdown listing every device. Pick one to jump straight to its page.

---

### 6.6 Training

**Teach PRAMAN to understand configuration syntax it has never seen — without touching the code or restarting anything.**

This is the screen that makes PRAMAN vendor-agnostic in practice rather than in principle. When a config contains a line no pattern pack recognises, the line is grouped into a **template** and queued here. You tell PRAMAN which canonical path that line means, and from that moment on every config containing that shape parses correctly.

> ### ⚠️ Read the on-screen warning
>
> The Training screen states this itself, and it is worth repeating:
>
> *"Teaching is approver-only and the mapping is stored under the authenticated operator, not under a name the client chose. What is still missing is transport security: the API speaks plain HTTP, so on a management network it belongs behind a reverse proxy terminating TLS. See docs/SECURITY.md."*
>
> There is no "admin id" field to fill in any more. The **Recorded as** row shows the account you are signed in as, taken from your session rather than typed, and that name is what gets stored with the mapping. If the Teach button is greyed out, you are signed in as a viewer or an auditor — teaching needs `approver`.

#### The six tiles

| Tile | Meaning |
|---|---|
| **Templates awaiting a mapping** | How many decisions are waiting for you. Hint: *"one decision each, however many devices they appear on"* |
| **Templates already mapped** | Done |
| **Mappings stored** | Total ever created |
| **Patterns in force** | Currently active |
| **Not in force** | Retired or superseded |
| **Canonical paths available** | How many of the 330 paths you can map to |

The "one decision each, however many devices they appear on" hint matters: if 200 routers all carry the same unusual line, that is **one** template and **one** decision, not 200.

#### The queue

| Column | Meaning |
|---|---|
| **Template** | The line shape, with its variable parts shown as numbered operands |
| **Vendor** | Which vendor it came from |
| **Lines** | How many raw lines collapsed into this template |
| **Devices** | How many devices show it |
| **Operands** | How many variable parts — or `flag only` if the line has none |
| **First seen at** | When |

**What is a template?** If three devices have `ntp server 10.0.0.1`, `ntp server 10.0.0.2` and `ntp server 192.168.1.1`, that is one template — `ntp server <1>` — with one operand. Teaching the template handles all three and every future one.

Rows expand. Click one (or press `Enter` on it) to open the teach form.

#### The teach form

| Field | What to do |
|---|---|
| **Canonical path** | Type the path this line means. There is an autocomplete list of all valid paths. If you type something that is not a real path, the field marks itself invalid and the button will not submit. |
| **Operand** | Only appears when the template has more than one variable part. Pick which one carries the value you care about. |
| **Recorded as** | Not a field — a read-only row showing the operator you are signed in as. It is taken from your session, never typed, and it is stored with the mapping. |
| **Note** | Optional. Why you made this decision. Your future self will thank you. |
| **Would capture** | A **live preview table** showing exactly what fact this mapping would produce from the real lines in the queue. It updates as you type. |
| **Teach this mapping** | Saves it. Takes effect immediately. |

**Always check the "Would capture" preview before you click.** It is the difference between mapping a path and mapping the *right* path, and it costs you two seconds.

#### Mappings in force

Everything currently active, each with a **Retire** button. Hovering the button explains: *"Withdraw the mapping. The record that it once applied is kept."*

Retiring is not deleting. Audits committed while the mapping was active keep their history — which is the whole point of a ledger.

#### Mappings that are not in force

Retired or superseded mappings, kept visible for the audit trail.

#### How this satisfies "no redeploy"

A short list explaining the mechanism. The claim is checkable: teach a mapping here, go to Overview → **Loaded runtime**, and watch the counters move. No restart, no code change, no deployment.

---

### 6.7 Topology

**A picture of your estate, drawn from the configs themselves.**

> **Read this first.** The screen says it plainly: **PRAMAN does no network discovery.** It never sends a packet. This map is inferred entirely from IP addresses written in the configuration files you uploaded. Two devices are drawn as connected when their interface addresses land in the same subnet. That is a reasonable guess about cabling — not a measurement of it.

**Control:** a **scope** dropdown — show *audited devices only*, or *all devices*.

#### The five tiles

| Tile | Meaning |
|---|---|
| **Devices on the map** | How many could be placed |
| **High-severity failures** | Devices with at least one high-severity failure |
| **Low or medium only** | Devices whose failures are all lower severity |
| **Everything applicable passes** | Devices that are clean |
| **Inferred links** | How many connections were guessed from shared subnets |

#### Map

Nodes coloured by risk, edges from shared subnets — with the no-discovery caveat printed beside it.

#### Where the estate is weak

A heatmap: devices down one axis, control families across the other, shaded by how bad each intersection is. This is the fastest way to spot a column that is red across every device — a whole category nobody has addressed.

#### Devices by risk

The same information as a sortable table, worst first. Use this one if the heatmap is hard to read precisely; it carries the same numbers.

#### Could not be read

Devices whose addressing could not be turned into a subnet. This is deliberate and specific — PRAMAN returns nothing rather than guessing for:

- `/31` and `/32` (point-to-point and host routes — no meaningful shared subnet)
- `/0` (a default route is not a subnet)
- malformed addresses
- IPv6

#### Excluded from the map

Devices left out because their identifiers look synthetic — ids containing `/`, `\` or `..`, which are path-traversal test artefacts rather than real devices.

**They are still named on screen.** Hiding them would be the wrong call: an excluded device that nobody can see is a device silently missing from your audit.

---

### 6.8 Ledger

**Proof that the reports have not been altered.**

Every time you commit an audit, PRAMAN writes a record that:

- is **hashed** (a fingerprint of its contents)
- **links to the previous record's hash**, forming a chain
- carries a **Merkle root** over all its findings (a fingerprint of the finding set)
- is **signed with an Ed25519 key**

Change any byte of any record and the chain breaks visibly. That is the point.

#### The banner

The first thing you see, in one of four states:

| State | Meaning |
|---|---|
| **All records verify** | Green. Everything checks out. |
| **N records do not verify** | Red. Something has been altered or the definitions changed. Details below. |
| **The ledger is empty** | You have not committed anything yet. |
| **Could not be verified** | The verifier itself failed. The banner says: ***"Treat this as unverified, not as verified."*** |

That last message is the honest one. A verifier that cannot run has told you nothing, and "nothing" must never be displayed as "fine".

#### Records that do not verify

Only appears when something failed. Includes a specific warning about a superseded hash definition — an older record can fail verification because the *definition* of the hash changed, not because anyone tampered with it — and points you at `MANUAL_COMMANDS.md` for how to handle it.

#### Records (N)

| Column | Meaning |
|---|---|
| **Seq** | Position in the chain |
| **Device** | Which device |
| **Committed** | When |
| **Record hash** | Shortened; hover for the full value |
| **Merkle** | Does the findings fingerprint match? |
| **Hash** | Does the record's own fingerprint match? |
| **Chain** | Does it correctly link to the record before it? |
| **Signature** | Is the cryptographic signature valid? |

**Those four checks are independent**, which is what makes the display diagnostic instead of a single opaque green light. A broken **Chain** with a valid **Hash** and **Signature** means a record was removed or reordered. A broken **Hash** means the record's own contents changed. Each check is a tri-state pill: pass, fail, or **`not checked`** — and `not checked` is displayed as itself, never as a pass.

There is also a small **chain strip** visualisation using `→` for an intact link and `⇸` for a broken one, so you can see *where* the chain breaks at a glance.

#### Score across the ledger

A trend line of compliance score over successive commits. This is your "are we getting better?" chart.

#### What is actually signed

A four-item list spelling out exactly what the signature covers — and, importantly, what it does not. Including this admission:

> Verification runs in the same process, which is convenient and is not independent.

In other words: if you want a genuinely independent check, verify the ledger with something that is not PRAMAN. The screen tells you that itself rather than letting you assume otherwise.

---

## 7. The two hidden screens

These have no nav tab. You reach them by clicking through from elsewhere. They are still fully bookmarkable.

### 7.1 One device

**Reached by:** clicking a hostname in Devices, a device name in Findings, or **Ingest this config for real** in Simulate.
**URL:** `#/device/<device-id>`

The complete report for one device. The **title** is the hostname; the **subtitle** is the detected vendor, OS family and version.

#### Title buttons

| Button | Notes |
|---|---|
| **Download signed PDF** | Only appears once the device has a committed audit. Downloads as `<hostname>-audit-<seq>.pdf`. |
| **Remediation plan** | Always present. Opens the fix list for this device. |
| **Commit audit** — or **Commit a new audit** if it already has one | Tooltip: *"Evaluate the stored facts and append a signed, chained record to the ledger."* While it runs, the button reads **Committing…** and is disabled so you cannot double-commit. On success you get a toast: *"Committed as seq #3 — 902 findings sealed under Merkle root a1b2c3d4."* The page then reloads itself so the history table, the PDF link and the trend all reflect the new record. |

#### If the device has never been audited

A notice panel at the top says so plainly — **"This device has no committed audit."** — and explains what that means. There is no PDF button until you commit.

#### Panel: Compliance

Four charts — gauge, result distribution, severity bars, framework bars — with this note:

> Recomputed, not read back from the ledger.

Which means: what you see is the verdict **as of right now**, against the currently loaded rules. If you taught a new mapping since you last committed, this will differ from the committed record. That is intentional and it is why the note exists.

#### Panel: Device identity

Hostname, vendor, OS family, OS version, serial numbers, hardware, **source file**, **config hash** (shortened), **when it was ingested**, and the **canonical fact count**.

When serials or hardware are missing, PRAMAN does not print a blank or a dash. It explains:

> not in a running-config — needs a `show version` or `show inventory` capture

That is an accurate statement about where the data lives. Serial numbers simply are not in a running configuration. If you want them, capture `show version` or `show inventory` output and include it in the same upload — which is what the two `device_identity/` fixtures demonstrate.

#### Panel: Findings (N)

The full findings table ([section 8.1](#81-the-findings-table)) — and on this screen, **remediation works**, because there is a real device and a real audit to resolve the fix against.

#### Panel: Configuration

The device's configuration, rebuilt from the stored facts. Two things to understand:

1. **It is marked `redacted`.** Passwords and keys were replaced before storage. What you see is not what is on the device.
2. **It is a reconstruction, not the original file.** PRAMAN stores facts, not files. It rebuilds a viewable config by taking the widest recorded text for each line number; lines nothing recorded come back blank. The panel tells you the **coverage percentage** and the **number of gaps**, so you always know how complete the reconstruction is.

Deep-linkable to a specific line: `#/device/edge-rtr-01?line=42`.

#### Panel: Facts from taught mappings (N)

Only appears if any. These are facts that exist **because a human taught PRAMAN a mapping** — their parser id ends in `+taught`. Separating them out means you can always tell machine-parsed facts from human-taught ones, which matters when you are auditing the auditor.

#### Panel: Audit history (N)

Every committed audit for this device, each with its own **PDF** and **Plan** buttons, plus a trend line across them. The PDF is that audit's report as it was signed. The **Plan** button opens the remediation plan for that **specific** audit — which is the difference between it and the **Remediation plan** button in the title bar, which uses the latest.

---

### 7.2 Remediation plan

**Reached by:** the **Remediation plan** button on a device's page (uses the latest audit), or the **Plan** button next to a specific entry in that device's Audit history.
**URL:** `#/remediation/<device-id>`

Every fix you need, in order, ready to copy.

> **The hard rule of this screen:** *"Nothing here is model-generated."* Every command comes from the benchmark publisher's own remediation text — CIS, DISA, NIST, ISO. PRAMAN resolves and formats it. It does not invent it. An AI-invented `configure terminal` command pasted onto a production router is exactly the failure mode this rule exists to prevent.

**Control:** a **scope** dropdown

| Scope | Shows |
|---|---|
| `fail` | Only failures (the default, and usually what you want) |
| `all` | Everything |
| `fail,error,unknown` | Failures plus the states that need a human look |

#### The six summary tiles

| Tile | Meaning |
|---|---|
| **Controls** | How many controls are in this plan |
| **With CLI** | How many have actual commands |
| **Manual only** | How many need a human procedure, not a command |
| **No published fix** | How many the publisher provided no remediation for |
| **Commands** | Total command count |
| **Runnable as-is** | How many need **no** editing before you run them, with a percentage |

That last tile is the honest one. It separates "here are 40 commands" from "here are 40 commands, 12 of which need your NTP server address filled in first".

#### Each entry card

| Element | Meaning |
|---|---|
| **Index** | Its position in the plan |
| **Control id** | e.g. `CIS 1.1.1` |
| **Framework** + **benchmark and version** | Which publication, which edition |
| **Title** | What the control requires |
| **Pills** | severity · kind (CLI / manual / none) · whether substitution is needed · risk of applying it |
| **Guidance** | The publisher's prose |
| **Steps** | Numbered commands, each with a **copy** button |
| **Placeholder warning** | Flagged on any step containing a value you must replace |
| **Verify** | How to confirm the fix worked |
| **Roll back** | How to undo it |
| **Source:** | Exactly which document this came from |
| **Notes** | Anything else |

#### Copy N runnable commands

One button that copies every command that needs **no** editing. Deliberately excludes anything with a placeholder, so you cannot paste `ntp server <YOUR_NTP_SERVER>` into a live device by accident.

#### How to read this

A five-item list at the bottom explaining the risk pills and the substitution markers. Read it once before you run anything.

---

## 8. Three shared pieces, explained once

These appear on several screens and behave identically everywhere.

### 8.1 The findings table

The most important component in the interface. You will see it on **Simulate**, on **one device**, and it is the engine behind the estate **Findings** view.

#### The filter bar

| Control | What it does |
|---|---|
| **Search** | Free text across control ids and titles |
| **Result** | Filter to one of the nine result values |
| **Severity** | high / medium / low / unknown |
| **Framework** | CIS / DISA STIG / NIST 800-53 / ISO 27001 |
| **Only failures** checkbox | The shortcut you will use most |
| **Clear** | Reset everything |

The dropdowns stay in sync with each other, so ticking "Only failures" also updates the Result dropdown. You never see a filter bar that disagrees with what it is showing.

#### The columns

| Column | Meaning |
|---|---|
| **Control** | The control id |
| **Framework** | Which standard |
| **Version** | Which edition of the benchmark |
| **Title** | What is required |
| **Result** | A coloured pill with the result word printed in it |
| **Severity** | high / medium / low |

The result pill always contains the **word**, not just a colour. Colour alone is not readable by everyone.

**Long lists load in pages of 40** and extend as you scroll, so a device with 900 findings does not freeze your browser.

#### Expanding a row

Click any row — or press `Enter` when it is focused — and it opens to reveal:

**Why this verdict** — a plain-language explanation of what the rule looked for and what it found.

**Evidence (N)** — the proof. Each item carries six fields:

| Field | Example | Why it is there |
|---|---|---|
| Source and line | `telnet_exposed.conf:42-45` | **Clickable** — jumps the configuration viewer to that line and flashes it |
| Which parser | `parser cisco_ios.vty` | Which pattern produced this fact |
| Confidence | `confidence 1.00` | How sure the parser was |
| The value found | | What was actually configured |
| The path | | Which canonical path it landed on |
| Or **"not present"** | | Stated explicitly when the finding rests on a setting's *absence* |

That last one matters. "You never configured `logging host`" is a real, valid finding with no line number. The interface says **not present** rather than showing an empty evidence block that looks like a bug.

**References** — links to the source publications.

**Remediation** — the fix. Fetched only when you expand a **failing** finding on a **real device** (there is nothing to fix on a pass, and Simulate has no stored device to resolve against). Shows:

- Pills: the kind of fix, its risk level, and whether it **needs your values**
- The publisher's guidance
- Numbered steps, each with a copy button
- A warning on any step containing a placeholder
- **Verify** and **Roll back** asides
- **Source:** the exact document
- And: *"Nothing here is model-generated."*

### 8.2 The configuration viewer

Your configuration, displayed with line numbers and verdict markers.

| Element | Meaning |
|---|---|
| **Gutter** | Line numbers down the left |
| **Coloured markers** | Lines that triggered a finding are highlighted by result colour |
| **Control badges** | Small labels showing which control(s) each marked line relates to |
| **Legend** | Above the viewer, explaining what each colour means |
| **`redacted` marker** | On device views. Hovering explains: *"Passwords and keys were replaced before this text was stored, so the value shown is not the value configured."* |

**When a line is both passing and failing, fail wins.** A green highlight on a line that also breaks a rule would be actively misleading.

Clicking a line reference in a finding's evidence scrolls the viewer there and **flashes the line for about 1.6 seconds** so you can see where you landed.

The syntax highlighting is a small hand-written tokeniser — about ten rules. It is deliberately not a full code editor. This whole interface ships with **zero dependencies**: no React, no build tool, no CDN, no downloaded fonts, no `node_modules`. Everything is plain browser JavaScript served by the same Python process. That is what makes it genuinely offline.

### 8.3 The charts

Seven chart types, all drawn as inline SVG in the browser.

| Chart | Shows |
|---|---|
| **Compliance gauge** | One score as an arc, with coloured bands |
| **Framework stacked bars** | Pass/fail split per framework |
| **Severity bars** | Failures by severity |
| **Result distribution** | How all nine result values are spread |
| **Trend line** | Score across successive audits |
| **Device heatmap** | Devices × control families, shaded by weakness |
| **Topology map** | The inferred network diagram |

#### Every chart has a table underneath it

Look for the collapsed **"Table view"** toggle beneath each chart. Open it and you get the exact numbers.

This is not decoration. It means:

- You can read every chart with a screen reader
- You can copy the numbers out
- You never have to squint at a bar to estimate a value
- Colour vision is never required to get the information

#### Two deliberate absences

- **The trend line does not render with fewer than two points.** A "trend" through one point is not a trend.
- **A chart with no data does not appear at all.** You will never see a labelled empty box where a chart was supposed to be.

#### The gauge bands are a PRAMAN convention

The gauge's colour bands (red under 50, orange 50–75, amber 75–90, green 90–100) are **PRAMAN's own choice**, not a published standard. The interface labels them as tool-defined wherever they appear.

---

## 9. Reading the colours

The palette is **frozen**, and it is shared byte-for-byte with the PDF generator. A test (`tests/test_frontend_palette.py`) fails if the two ever drift apart.

Why go to that trouble? Because a chart on screen and the same chart in the filed report are the same chart. If you read a green bar on screen and an amber one in the PDF, you have been shown two different audits.

| Colour | Meaning |
|---|---|
| 🟢 Green | `pass` |
| 🔴 Red | `fail` |
| 🟠 Orange | `error` |
| 🟡 Amber | `unknown` |
| 🟢 Teal | `fixed` |
| ⚫ Grey | `notapplicable` |
| ⚪ Pale grey | `notchecked` |
| ⚪ Palest grey | `notselected` |
| 🔵 Blue | `informational` |

**Result colours never change between light and dark mode.** Two screenshots of one audit must not disagree.

**Frameworks** get four fixed colours: CIS blue, NIST orange, DISA STIG green, ISO 27001 amber. A fifth framework would fold to a neutral rather than get an invented hue — a colour nobody validated is a colour that fails a colourblind check in front of an auditor.

**Severity** uses a single-hue red ramp (light red → red → dark red), which passes colourblind checks where a five-colour severity palette does not. Severity `unknown` borrows the amber "unknown" colour, because it means *not rated* — not a fourth rung on the scale.

**Legends always list the two verdicts first**, then the seven non-verdicts. That reading order is itself an honesty feature: `notchecked` sitting between `pass` and `fail` would invite you to read it as a third verdict.

---

## 10. Your first ten minutes — a full walkthrough

Follow this end to end and you will have used every major feature.

**1. Start the server.**

```bash
.venv/Scripts/python.exe scripts/serve.py
```

**2. Open** <http://127.0.0.1:8012>. You get a sign-in box.

If you have not created an account yet, it tells you so — stop here, run the command in [Step 2](#step-2--create-your-account-once) in another terminal, and come back. The server does not need restarting.

Sign in as your `approver` account. You land on **Overview**. Everything is empty. That is correct. Your name and role are in the top right; that is what will end up inside every audit record you commit.

**3. Look at the AI escalation ladder.** Tier 0 is on. Tiers 1–3 are probably `not loaded`. **This is a supported configuration, not a broken install.** Compliance results do not depend on them.

**4. Go to Simulate.** Click **Insecure router**, then **Check**.

You now have a full audit of a device that never existed. Scroll through: the gauge is red, the findings table is pre-filtered to failures, and the configuration viewer shows exactly which lines caused them. Nothing was stored.

**5. Expand a failing finding.** Click any red row. Read **Why this verdict**, then click the blue line reference in **Evidence** — the configuration viewer jumps to that line and flashes it. That round trip from verdict → evidence → the actual line of config is the core of the whole tool.

**6. Click the "Unknown vendor lines" sample, then Check.** Scroll to **Unrecognised lines**. These are lines no pattern recognised. Look at the **Proposed path** and **Confidence** columns, and note anything marked `abstained` — that is PRAMAN refusing to guess.

**7. Go to Upload.** Click **Choose files**, navigate to `praman/test_configs/realistic/`, select **all five** files, upload.

Watch the progress bar and the results table fill in. Note the **Unrecognised lines** column.

**8. Click "Review 5 ingested device(s)."** You are on **Devices**. Five rows. Every **Latest audit** cell says "never audited" — because uploading is not auditing.

**9. Click a hostname.** You are on that device's page. Compare it to what Simulate showed you: same charts, same findings table, but now with a **Device identity** panel and an **Audit history** panel. Note that serials read *"not in a running-config"* — an honest statement about where that data lives.

**10. Click "Commit audit."** *Now* something permanent exists.

**11. Go back to Devices** and commit two or three more, so you have a trend to look at.

**12. Go to Ledger.** Green banner. Records table with four independent check columns, all green. Read **"What is actually signed"** — including the admission that verification runs in the same process and is therefore not independent.

**13. Go to Overview.** It is populated now: Estate pass rate has a number, Ledger integrity says `verified`, the trend line has points, and Recent commits lists what you just did.

**14. Go to Findings.** Every failing control across all five devices. Look at **Failing everywhere** first — those are your estate-wide problems. Then look at the **Also passing on** column to find controls somebody has already solved somewhere.

**15. Go to Topology.** A map inferred purely from IP addresses — no packets sent. Check the **Where the estate is weak** heatmap for a column that is red across every device.

**16. Go to Training.** Every unrecognised line from your five uploads, grouped into templates. Expand one, type a canonical path, watch the **Would capture** preview update live. Check that **Recorded as** names you. Click **Teach this mapping**. (If it is greyed out you are not an `approver` — teaching and committing are the two approver-only actions.)

**17. Go back to Overview → Loaded runtime.** The counters have moved. No restart. That is the "new formats without redeploy" claim, demonstrated.

**18. Go to Devices → a device → Remediation plan.** Every fix, from the publisher's own text, with copy buttons, placeholder warnings, verify steps and roll-back steps. Check the **Runnable as-is** tile before you copy anything.

**19. Click Download signed PDF.** The signed report, with the same charts in the same colours as the screen.

**20. Click ◐.** Everything redraws in the other theme, charts included, and your choice is remembered.

---

## 11. When something looks wrong

| What you see | What it means | What to do |
|---|---|---|
| Stuck on "Starting the interface…" | You opened the HTML file directly (`file://`). Browsers block module imports from the filesystem. | Start the server and use `http://127.0.0.1:8012`. |
| The footer shows a `uvicorn` command | The interface could not reach `/health`. | The server is not running, or you are on the wrong port. |
| **Estate pass rate** is `—` but you have devices | You have not committed any audits. The tile reads from the **ledger**. | Commit an audit from a device page or the Devices tab. |
| **Ledger integrity: unknown** | The verifier could not be reached. | This means **unverified**, not verified. Check the server is healthy. |
| A tier says `not installed` | You never downloaded that model. | Nothing is broken. Verdicts do not use the AI. If you want the tiers, follow `../MANUAL_COMMANDS.md`. |
| Tier 3 says `no weights on disk` | The 2.4 GB model is not downloaded. | `MANUAL_COMMANDS.md`, the download step. |
| Tier 3 says `not reachable · checked 28s ago` | The model is on disk but its server is not running. | Start `llama-server` — `MANUAL_COMMANDS.md` Step 6 — then reload. |
| Almost everything is `notchecked` | Normal. PRAMAN automates 454 of 3,366 controls. | Read the **Coverage of the standard** table. `docs/GAPS.md` argues the unautomated controls benchmark by benchmark, with the reason. |
| A file was rejected on upload | Not a config, no pattern pack for that vendor, or a size limit. | Read the **Detail** column. Nothing partial was stored. |
| "Send one archive at a time." | You dropped a `.zip` together with loose files. | Send the ZIP by itself, or the loose files by themselves. |
| The archive was refused for a limit | Zip-bomb guard doing its job. | Split it into batches. Limits are in [section 4](#method-4--upload-a-zip-of-an-entire-estate). |
| A control fails on **every** device | Either a real estate-wide problem **or** a rule no config can satisfy. | Investigate before filing 40 tickets. The warning on the Findings screen says exactly this. |
| Serials and hardware are empty | They are not in a running-config. | Include `show version` / `show inventory` output in the upload. See the two `device_identity/` fixtures. |
| Devices "could not be read" on Topology | `/31`, `/32`, `/0`, malformed, or IPv6 addressing. | Expected. PRAMAN returns nothing rather than guessing. |
| Devices "excluded from the map" | Their ids look synthetic (contain `/`, `\`, or `..`). | Test artefacts. They are named on screen rather than hidden. |
| A ledger record does not verify | Possibly a superseded hash definition rather than tampering. | Read the warning panel on the Ledger screen and `MANUAL_COMMANDS.md`. |
| No trend chart with one commit | By design. | Commit a second audit. |
| A device's on-screen score differs from its committed record | The screen recomputes against **current** rules; the record is what was signed **then**. | Both are correct. Re-commit if you want them to match. |

---

## 12. Cheat sheet

### Every screen

| Tab | URL | Use it to |
|---|---|---|
| **Overview** | `#/dashboard` | See the whole estate and what is installed |
| **Upload** | `#/upload` | Get configs in — file, folder, or ZIP |
| **Simulate** | `#/simulate` | Test a config without storing it |
| **Devices** | `#/devices` | List everything, commit audits, get PDFs |
| **Findings** | `#/findings` | Find estate-wide problems |
| **Training** | `#/training` | Teach new syntax, no restart |
| **Topology** | `#/topology` | See the inferred map and where you are weak |
| **Ledger** | `#/ledger` | Prove nothing was altered |
| *One device* | `#/device/<id>` | The full report for one device |
| *Remediation* | `#/remediation/<id>` | Every fix, ready to copy |

### Useful URLs to bookmark

```
#/findings?result=fail&severity=high      All high-severity failures
#/device/edge-rtr-01?line=42              A device, scrolled to line 42
#/simulate?sample=Insecure router         Simulate with a sample pre-loaded
```

### The five things worth remembering

1. **Uploading is not auditing.** No signed record and no PDF until you **Commit**.
2. **`notchecked` is not a pass.** Always read the score next to the coverage.
3. **Simulate stores nothing.** Safe for production configs.
4. **No model decides a verdict, ever.** The AI only suggests what unknown *lines* mean.
5. **There is a login, but no TLS.** Your name goes inside the signed record; your password crosses the wire in clear text. Keep it on loopback.

### Where to read more

| Document | Answers |
|---|---|
| [`README.md`](README.md) | What the project is, and how every number is verified |
| [`test_configs/README.md`](test_configs/README.md) | What each of the ten test configs proves, with measured numbers |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | How the pieces fit together |
| [`docs/GAPS.md`](docs/GAPS.md) | **Every control PRAMAN does not check, and why** |
| [`docs/SECURITY.md`](docs/SECURITY.md) | Threat model — read before exposing the port |
| [`docs/DEMO.md`](docs/DEMO.md) | The two-minute demo, shot by shot |
| [`../MANUAL_COMMANDS.md`](../MANUAL_COMMANDS.md) | The heavy steps — model downloads, training — with cost and rollback |
| `http://127.0.0.1:8012/docs` | Interactive API documentation, live |
