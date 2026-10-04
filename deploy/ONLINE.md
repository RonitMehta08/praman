# Hosted demo deployment

PRAMAN has two valid operating profiles:

| Profile | Where configs are processed | Best use |
|---|---|---|
| **Offline appliance** | The assessor's laptop or an internal machine | Real sensitive configurations and air-gapped assessments |
| **Hosted demo** | The web service's private runtime and SQLite volume | A public demo using only the shipped sample configurations |

These profiles use the same FastAPI app, deterministic rules engine, frontend and
ledger. Hosting the app does not make the offline claim false; it gives users a
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
    sh deploy/build-online.sh
   ```

4. **Start command:**

   ```bash
   sh deploy/start-online.sh
   ```

5. **Health-check path:** `/health`.
6. **Environment variables:**

   | Variable | Value |
   |---|---|
    | `SENTINEL_AI_BACKEND` | `classifiers` |
    | `PRAMAN_SIGNUP_ENABLED` | `true` |
    | `HF_HUB_OFFLINE` | `1` |
    | `TRANSFORMERS_OFFLINE` | `1` |
    | `OMP_NUM_THREADS` | `1` |
    | `TOKENIZERS_PARALLELISM` | `false` |

   The start script sets `HOST=0.0.0.0` for the provider. Do not change the
   default local behaviour of `scripts/serve.py`; loopback is the safe offline
   default.

On Render you can instead choose **New → Blueprint**, connect the repository,
and use the root-level `render.yaml`. It defines the same free, disposable demo
with self-service signup. The `.python-version` file pins the
Python runtime even when you create a Web Service manually.

### Windows local startup

The shell start command above runs on Render's Linux host. In Windows PowerShell,
from the project folder, start the app:

```powershell
powershell -File deploy/start-windows.ps1
```

Open `http://127.0.0.1:8012` and use **Create an account**. Local startup does not
create a public URL.

Keep the hosted service at **one application instance and one Uvicorn worker**.
PRAMAN intentionally uses one SQLite file and an in-process background-job
queue; adding multiple workers or replicas would give them separate job queues
and can cause SQLite write contention. Horizontal scaling is a later
multi-tenant architecture change, not a setting to turn on for the demo.

## Persistence

The hosted demo works without a volume for a short-lived demo session, but a
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

1. Open the public HTTPS URL, select **Create an account**, and enter your own
   username, role and password. Choose **Approver** for the complete demo.
2. Upload only files from `test_configs/`, or use the Simulate view with a sample
   configuration.
3. Demonstrate **Simulate** first; it does not write to the ledger.
4. Ingest a sample, commit it as the approver, open the findings, and download
   the signed report.
5. Verify `/health` shows `ai.ai_backend=classifiers`, `tier1_tfidf=true` and
   `tier2_setfit=true`. Explain that these models suggest parser mappings while
   compliance verdicts remain deterministic.

The hosted demo uses the committed TF-IDF and SetFit weights on CPU. The build
installs CPU-only PyTorch first, installs pinned SetFit dependencies, and runs
`scripts/check_ai_runtime.py` with Hugging Face networking disabled. A missing
file or model-load failure stops the build instead of producing a misleading
green model badge. The service loads models lazily and caches them on first use.
Qwen/llama.cpp is not required for this profile.

### Updating an existing Render service

Changing files in your checkout does not update Render until the changes reach
the GitHub branch that the service deploys. In the existing service's settings,
change the **Build Command** to `sh deploy/build-online.sh` and the **Start Command**
to `sh deploy/start-online.sh`. In **Environment**, change the old
`SENTINEL_AI_BACKEND=none` to `classifiers` and add the variables in the table
above, then deploy the updated branch. Dashboard-configured services do not
automatically inherit every change in `render.yaml`.

Bootstrap credentials are now optional, for a deployment owner who wants a
pre-provisioned account. Visitors do not need them. `PRAMAN_SIGNUP_ENABLED=false`
disables self-service registration. Account passwords, roles and sessions persist
in SQLite, subject to the persistence rules above.

The CPU PyTorch/SetFit runtime needs more memory than the deterministic engine.
If the provider kills the process during the first SetFit load, check the service
memory graph and allocate enough RAM for the model runtime. A free disposable
service may need a larger plan for the full classifier demonstration.

## Describing the deployment's security boundaries

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
