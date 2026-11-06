# Azure student-credit VM deployment

Use one Linux VM for the FastAPI app, SQLite and optional llama.cpp process.
nginx terminates HTTPS; the backend listens only on `127.0.0.1:8012`, and Qwen
only on `127.0.0.1:8080`. One Uvicorn process preserves the in-process job queue.
Use only shipped sample configurations in this public demonstration.

## 1. Create the VM

In Azure Portal, open **Virtual machines → Create → Azure virtual machine**:

| Field | Initial choice |
|---|---|
| Subscription | Your Azure for Students subscription with the $100 credit |
| Resource group | Create `praman-demo-rg` for this deployment |
| VM name | `praman-demo` |
| Region | A nearby region allowed by your subscription; West India may reject individual SKUs |
| Image | **Ubuntu Server 22.04 LTS, x64, Gen2** |
| Size | **Standard_D2as_v5: 2 vCPUs, 8 GiB RAM**, if available |
| Availability | No infrastructure redundancy required for the demo |
| Authentication | SSH public key; username **azureuser** |
| OS disk | **64 GiB Standard SSD LRS**, managed/persistent, not ephemeral |
| Public IP | Standard IPv4 (static) |
| Networking | SSH 22 from your IP; HTTP 80 and HTTPS 443 for the public site |

ASSUMPTION: 8 GiB is our starting capacity for the classifiers and a single
CPU-only Qwen slot, not a measured peak-memory requirement. Verify it after load.
This size has no GPU. Qwen latency must be measured before relying on it in a demo.
Do not open 8012 or 8080 in the network security group.

If Azure shows `NotAvailableForSubscription` for `Standard_D2as_v5`, do not keep
retrying that same selection. In **See all sizes**, filter for **x64**, at least
**2 vCPUs** and **8 GiB RAM**, then choose the first available option in this
order: `Standard_D2s_v5`, `Standard_D2as_v4`, `Standard_D2s_v4`, then
`Standard_B2as_v2`. These are fallback candidates, not availability promises; use
only a size the portal marks selectable for this subscription and region. Prefer a
current D-series size over B-series. `Standard_B2as_v2` is burstable and should be
used as a classifier-first fallback; defer Qwen until memory and latency checks
pass. Do not select an ARM size for this first deployment because the current
PyTorch/SetFit path has not been verified on ARM.

If restrictions recur across regions, inspect the subscription's actual SKU
restrictions instead of continuing to guess regions. Open Azure Cloud Shell in
**Bash** (choose a session without a storage account when offered), confirm the
active subscription, then query the region that failed:

```bash
az account show --query '{Name:name,State:state}' --output table
az vm list-skus --location eastus --resource-type virtualMachines --size Standard_D2 --all --output table
az vm list-skus --location eastus --resource-type virtualMachines --size Standard_B2 --all --output table
az vm list-usage --location eastus --output table
```

Select the Azure for Students subscription in Cloud Shell if the first command
names another account. `Restrictions: None` means no SKU restriction was reported,
not guaranteed allocation capacity. `type: Zone` can be a zone-specific restriction;
use **No infrastructure redundancy required** to check a regional deployment.
`type: Location` applies to the region. The usage table reports regional/family
vCPU quotas; a quota problem is distinct from a SKU restriction. If the needed
sizes remain blocked, request SKU access through Azure Support rather than
assuming an upgrade or a quota increase will automatically unlock them.

Do not create a VM with 4 GiB if Qwen is a requirement. Use the deterministic/
classifier demo there only, or select an available region/size after inspecting
the returned restrictions and quotas.

Review the displayed compute price before creating the VM. Also account for its
managed disk, public IPv4 and outbound traffic. Region availability, quota and
student-subscription restrictions can prevent a particular size from being
selected. If this size is unavailable, record the available x64 sizes with
at least 8 GiB and their prices before choosing a replacement.

Enable **Auto-shutdown** during preparation, with the correct time zone. Keep it
outside the judging window when the link must remain available. Create a budget
alert at the resource-group scope; budget alerts do not stop spending. Portal
**Stop** should leave the VM **Stopped (deallocated)** to stop compute billing;
disks and the public IP can still incur charges. The $100 credit does not imply
12 months of continuous operation on this VM.

Download the generated private SSH key and keep it on your machine. Once the VM
is created, open its **Public IP → Configuration**, choose a unique DNS name label
and copy the full DNS name shown by Azure. Use that exact hostname below, including
any extra scope/hash component. A purchased domain is not required for this path.
Set the public IP's idle timeout to 10 minutes for long report requests.

## 2. Connect and install

From Git Bash on your Windows laptop (replace both placeholders):

```bash
ssh -i "$HOME/Downloads/praman-demo_key.pem" azureuser@YOUR_VM_PUBLIC_IP
```

Run **Step 18a in `MANUAL_COMMANDS.md`** inside that SSH session. It clones the
standalone repository into `/opt/praman`, creates a Python 3.10 venv and runs the
existing CPU-classifier build. Python 3.12 from Ubuntu 24.04 is outside the current
project support range, which is why the image is explicitly 22.04.

These files must be present in the VM checkout: `deploy/start-vm.sh`,
`deploy/praman.service`, `deploy/praman-qwen.service`,
`deploy/start-qwen-cpu.sh`, and `deploy/praman-vm.env.example`. If they have not yet
been published to GitHub, copy them from the laptop with `scp` to
`azureuser@YOUR_VM_PUBLIC_IP:/opt/praman/deploy/` before continuing.

## 3. Start the application

Inside the VM:

```bash
cd /opt/praman
sudo install -d -m 0750 /etc/praman
sudo install -m 0600 deploy/praman-vm.env.example /etc/praman/praman.env
sudo install -m 0644 deploy/praman.service /etc/systemd/system/praman.service
sudo systemctl daemon-reload
sudo systemctl enable --now praman
sudo systemctl status praman --no-pager
curl --fail --max-time 30 http://127.0.0.1:8012/health
```

The environment file is read by systemd as root, then the app runs as `azureuser`.
If you chose another login name, update `User` and `Group` in both unit files.
Do not copy your laptop's database or signing keys: the hosted demo creates its
own identity and database. No bootstrap password is required for public signup.

To test before HTTPS setup, open a second Git Bash terminal on your laptop:

```bash
ssh -i "$HOME/Downloads/praman-demo_key.pem" -N \
  -L 8012:127.0.0.1:8012 azureuser@YOUR_VM_PUBLIC_IP
```

Open `http://127.0.0.1:8012`, create an Approver account and try the Simulate
examples. The tunnel protects this initial connection while only SSH is exposed.

## 4. Publish HTTPS

Run **Step 18b in `MANUAL_COMMANDS.md`**. It installs nginx from the publisher's
stable Ubuntu repository, obtains a certificate for your Azure DNS hostname and
adapts the existing `deploy/nginx/praman.conf`. The distro's older nginx can lack
directives used by this template; use the publisher package rather than deleting
cookie flags or HTTP/2 directives to make an old version accept it.

The public entry point is `https://YOUR_AZURE_DNS_NAME`. Verify signup, signout,
login, a Simulate example, sample ingestion, commit and PDF download there.
Public `/health` is intentionally denied by the proxy; check it over SSH.

## 5. Add Qwen after the classifier workflow succeeds

Run **Step 18c in `MANUAL_COMMANDS.md`** to build Linux llama.cpp at pinned tag
`b10610`, copy the existing GGUF from your laptop and verify a real completion.
Keep the app in `classifiers` mode until that check succeeds. Then edit
`/etc/praman/praman.env`, set `SENTINEL_AI_BACKEND=full`, and restart `praman`.

The API's existing LLM timeout is 30 seconds. The direct completion check in
Step 18c uses that same deadline; a healthy model badge only proves availability,
not inference speed. A slow CPU result needs investigation before enabling Tier 3.
Validating paths against the schema and human approval remain the current mapping
guards; deployment does not add grammar-constrained decoding to the backend.

## 6. Persistence, updates and diagnosis

The managed OS disk holds `/opt/praman/data/praman.db`, `data/private/`, learned
mapping/pattern files, reports and models across process restarts and VM
deallocation. **Preserve the checkout** during updates; do not replace it with a
fresh clone. Durable disk is not a backup, and deleting the VM/resource group can
delete it. Back up SQLite with its backup API (not a live `.db` file copy) and
preserve the associated signing keys and learned files together. Jobs currently
in memory are lost on app restart.

Before an update, inspect `git status`: training can modify tracked mapping files.
Resolve those changes deliberately before pulling. After updating dependencies,
restart the service and repeat the workflow checks. Changes to unit files need
`systemctl daemon-reload`; changes to the environment file need an app restart.

For a failing example or 502, collect the actual VM evidence:

```bash
sudo journalctl -u praman -n 100 --no-pager
sudo journalctl -u praman-qwen -n 100 --no-pager
sudo journalctl -k --since '30 minutes ago' --no-pager
sudo systemctl show praman praman-qwen -p MemoryCurrent -p MemoryPeak -p NRestarts
free -h
df -h /opt/praman
curl --fail --max-time 30 http://127.0.0.1:8012/health
sudo nginx -t
```

Check `/var/log/nginx/error.log` if the backend works locally but the proxy fails.
OOM kills and synchronous work blocking async request handlers are distinct
causes; a larger VM does not by itself prove either issue resolved.

## Sources checked for this deployment

- [Azure VM portal quickstart](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/quick-create-portal)
- [Dasv5 sizes](https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/general-purpose/dasv5-series)
- [Basv2 sizes](https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/general-purpose/basv2-series)
- [Public IP and DNS labels](https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses)
- [Budget alerts](https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/tutorial-acm-create-budgets)
- [SKU availability troubleshooting](https://learn.microsoft.com/en-us/azure/azure-resource-manager/troubleshooting/error-sku-not-available)
- [nginx Ubuntu packages](https://nginx.org/en/linux_packages.html)
- [Certbot usage and renewal](https://eff-certbot.readthedocs.io/en/stable/using.html)
- [llama.cpp b10610](https://github.com/ggml-org/llama.cpp/releases/tag/b10610)
- [Pinned CPU build instructions](https://raw.githubusercontent.com/ggml-org/llama.cpp/b10610/docs/build.md)
- [Pinned server flags/API](https://raw.githubusercontent.com/ggml-org/llama.cpp/b10610/tools/server/README.md)
