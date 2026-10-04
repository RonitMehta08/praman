# Hosted demo deployment

PRAMAN has two valid operating profiles:

| Profile | Where configs are processed | Best use |
|---|---|---|
| **Offline appliance** | The assessor's laptop or an internal machine | Real sensitive configurations and air-gapped assessments |
| **Hosted demo** | The web service's private runtime and SQLite volume | A hackathon link using only the shipped sample configurations |

These profiles use the same FastAPI app, deterministic rules engine, frontend and
ledger. Hosting the app does not make the offline claim false; it gives judges a
convenient way to inspect a demonstration. It does mean that a config uploaded to
the hosted URL leaves the user's machine, so never upload a real customer or
production configuration to the public demo.

## Fastest path to a live URL

Use a Python web-service provider that supports a build command, a start command,
environment variables, HTTPS termination, and preferably a persistent disk. The
dashboard fields are:

1. **Repository/root directory:** leave this **blank** for the standalone
   `RonitMehta08/praman` repository. `backend/`, `frontend/` and `deploy/` are at
   its root. Set `praman` only when deploying the larger `TEST1` workspace repo.
2. **Runtime:** Python 3.10 or another Python version accepted by
   `pyproject.toml` (`>=3.10,<3.12`).
3. **Build command:**

   ```bash
   python -m pip install -r requirements.lock.txt
   ```

4. **Start command:**

   ```bash
   sh deploy/start-online.sh
   ```

5. **Health-check path:** `/health`.
6. **Environment variables:**

   | Variable | Value |
   |---|---|
   | `SENTINEL_AI_BACKEND` | `none` |
   | `PRAMAN_BOOTSTRAP_USERNAME` | a short lowercase demo username, for example `demo` |
   | `PRAMAN_BOOTSTRAP_PASSWORD` | a provider secret, at least 12 characters |
   | `PRAMAN_BOOTSTRAP_ROLE` | `approver` for the complete demo flow |

   The start script sets `HOST=0.0.0.0` for the provider. Do not change the
   default local behaviour of `scripts/serve.py`; loopback is the safe offline
   default.

On Render you can instead choose **New → Blueprint**, connect the repository,
and use the root-level `render.yaml`. It defines the same free, disposable demo
and prompts for `PRAMAN_BOOTSTRAP_PASSWORD`. The `.python-version` file pins the
Python runtime even when you create a Web Service manually.

### Windows local startup

The shell start command above runs on Render's Linux host. In Windows PowerShell,
from the project folder, create a local operator once and then start the app:

```powershell
.\.venv\Scripts\python.exe scripts\manage_users.py add --username demo --role approver
powershell -File deploy/start-windows.ps1
```

Open `http://127.0.0.1:8012`. Local startup does not create a public URL.

Keep the hosted service at **one application instance and one Uvicorn worker**.
PRAMAN intentionally uses one SQLite file and an in-process background-job
queue; adding multiple workers or replicas would give them separate job queues
and can cause SQLite write contention. Horizontal scaling is a later
multi-tenant architecture change, not a setting to turn on for the demo.

## Persistence

The hosted demo works without a volume for a short-lived judging session, but a
restart or redeploy can erase the SQLite database on providers with ephemeral
filesystems. If the provider offers a mounted persistent disk, set:

```text
PRAMAN_DATABASE_PATH=/var/data/praman.db
```

Replace `/var/data` with the mount path assigned by the provider. The directory
must be writable by the service. The application creates the database, schema,
ledger tables and signing keys on first use; do not copy a local
`data/praman.db`, `data/private/`, or real device configuration into the public
deployment.

The signing keys currently live in `data/private/`, independently of the database
override. A durable deployment must also preserve that directory across redeploys;
preserving only the database can leave historical ledger signatures unverifiable.
The shipped free Render Blueprint is intentionally disposable and has no disk.

If no persistent disk is available, treat the service as a disposable demo:
seed it with the shipped fixtures, log in, and demonstrate the flow during the
live session. The offline package remains the durable product profile.

## Demo preparation

After the service is live:

1. Open the public HTTPS URL and sign in with the bootstrap credentials.
2. Upload only files from `test_configs/`, or use the Simulate view with a sample
   configuration.
3. Demonstrate **Simulate** first; it does not write to the ledger.
4. Ingest a sample, commit it as the approver, open the findings, and download
   the signed report.
5. Verify `/health` shows `SENTINEL_AI_BACKEND=none` and explain that compliance
   verdicts are deterministic and do not require an online model.

The hosted demo does not need Tier 3 Qwen/llama.cpp. Disabling it makes the
deployment smaller, cheaper and easier to reproduce while leaving the compliance
verdict path unchanged.

## Security language for the submission

Use wording like:

> “PRAMAN is offline-first: the full audit path runs without network access, and
> sensitive configurations can stay on the assessor's machine. We also provide a
> hosted demonstration for evaluators. The hosted instance is served over
> HTTPS and is populated only with synthetic/sample configurations; production
> deployments should run the same application inside the organisation's trusted
> network or air-gapped environment.”

Avoid saying that the public demo has the same privacy boundary as the offline
appliance. The strongest security claim is precisely that deployment choice is
left to the operator.
