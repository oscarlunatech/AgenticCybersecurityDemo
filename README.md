# oscarlunatech.com — EC2 + Caddy + Let's Encrypt + Live Lab

A single Ubuntu EC2 instance, provisioned entirely by Terraform, that runs:
- **Caddy** serving the landing page over auto-renewing Let's Encrypt HTTPS
- a **Node orchestrator** that launches a hardened, per-session Docker container
  when a visitor clicks "Start demo" on `/lab.html`, shows it in an iframe, and
  destroys it after 30 minutes

Everything below — Docker, Node, Caddy, the demo image, the orchestrator service,
and all web content — is installed by the instance's cloud-init at boot, so a single
`terraform apply` reproduces the whole working box from scratch.

```
visitor ──https──> Caddy (TLS) ──┬─ /            -> static site (/var/www/html)
                                 ├─ /lab.html     -> Start-demo control page
                                 └─ /api, /demo   -> orchestrator (127.0.0.1:8080)
                                                        └─ per-session container on "labnet"
```

## Project layout
- `terraform/` — all infrastructure, including the cloud-init template that bakes in the lab
- `site/index.html` — the landing page
- `lab/orchestrator/` — the Node service (source of truth; embedded into cloud-init)
- `lab/demo-image/` — the per-session container image
- `lab/frontend/lab.html` — the Start/Stop control page

## 1. AWS credentials

Same as before — keys never go in the repo. Either:
```bash
aws configure                 # stores in ~/.aws, recommended
# or
cp .env.example .env          # paste keys into .env, then:
source .env
```
Use a dedicated IAM user, not root.

## 2. Deploy

```bash
cd terraform
terraform init
terraform apply
```

This creates the security group, IAM role, instance, Elastic IP, and DNS records.
The instance's cloud-init then installs Caddy and starts serving.

## Dev vs prod (two isolated boxes)

The environment is driven by the **Terraform workspace** — the workspace name *is*
the environment. The default workspace is prod; a workspace named `dev` is dev.

- **prod** → `oscarlunatech.com`, real Let's Encrypt cert, `www` redirect.
- **dev** → `dev.oscarlunatech.com`, Let's Encrypt **staging** cert (browser shows an
  untrusted warning, but you can destroy/rebuild endlessly with no rate limit), no `www`.

They live in separate state and use environment-prefixed names (`oscarlunatech-dev-*`
vs `oscarlunatech-prod-*`), so they never collide.

```bash
# prod (default workspace)
terraform apply

# dev — create the workspace once, then use it
terraform workspace new dev          # first time only
terraform workspace select dev
terraform apply                      # builds dev.oscarlunatech.com on staging certs

terraform destroy                    # throw dev away anytime; prod is untouched
terraform workspace select default   # back to prod
```

To keep the rebuildable dev box off the public internet, lock it to your IP:
```bash
terraform apply -var="restrict_to_cidr=YOUR.IP.ADDR/32"
```

**About the certificate timing:** Caddy can only get a cert once DNS for the host
resolves to the instance and ports 80/443 are reachable. On a fresh deploy, DNS may
take a few minutes to propagate; Caddy retries automatically, so the site goes from
"not secure yet" to HTTPS on its own within a few minutes. No action needed.

## 3. Visit

```
https://oscarlunatech.com
```
(www redirects to the apex.)

## Accessing the server

SSH is open to the internet with key-only auth (no passwords). Connect with your
local key:
```bash
ssh ubuntu@$(terraform -chdir=terraform output -raw public_ip)
```
By default Terraform imports `~/.ssh/id_ed25519.pub`. If your key is RSA, set
`-var="public_key_path=~/.ssh/id_rsa.pub"` on apply (and SSH with that key).

To restrict SSH to just your IP later, change the SSH `cidr_blocks` in `ec2.tf` from
`0.0.0.0/0` to `YOUR.IP.ADD.RESS/32` and re-apply.

## IAM user permissions (simpler now)

Because SSM is gone, Terraform no longer creates any IAM role, so your
`oscarlunatech-terraform` user **no longer needs IAM permissions at all**. Attach
just two managed policies:
- `AmazonEC2FullAccess`
- `AmazonRoute53FullAccess`

You can drop `IAMFullAccess` entirely — that removes the privilege-escalation risk
you asked about, since the user can no longer touch identities or policies.

## Updating content or the lab

All web content and lab code lives in this repo and is baked in at boot. To change
anything — the landing page, `lab.html`, the orchestrator, or the demo image — edit
the file here and re-apply:
```bash
terraform apply
```
Because `user_data_replace_on_change = true`, this **replaces the instance** with a
fresh one built from your updated files. The Elastic IP and DNS survive, so the site
returns at the same address (Caddy re-fetches its cert within a few minutes).

For a quick one-off tweak without a full rebuild, you can still SSH in and edit files
in place (`/var/www/html/`, `/opt/demo-orchestrator/`), then `sudo systemctl restart
demo-orchestrator` or `sudo systemctl reload caddy`. But the repo is the source of
truth — anything changed only on the box is lost on the next apply.

## Verifying the lab after deploy

cloud-init takes a few minutes on first boot (it installs Docker, Node, and Caddy and
builds the image). Watch progress by SSHing in and tailing the log:
```bash
sudo tail -f /var/log/cloud-init-output.log
```
Once done:
- `https://oscarlunatech.com/lab.html` → press Start demo, container loads in the iframe
- `sudo systemctl status demo-orchestrator` → active (running)
- `docker ps` → a `demo-site` container appears on Start, vanishes on Stop/expiry

## Changing the machine later (your EBS question)

The root volume is an encrypted **gp3 EBS** volume that persists independently of the
instance. To change power:

- **Resize the instance:** edit `instance_type` (e.g. to `t3.small`) and `terraform
  apply`. This stops and starts the instance; the EBS data and the Elastic IP both
  survive, so your DNS keeps working.
- **Grow the disk with no downtime:** raise `root_volume_gb` and apply, then extend
  the filesystem on the box (`sudo growpart` + `sudo resize2fs`).

## Cost (always-on)

- t3.micro: ~$7.50/mo (largely covered by free tier on a new account for 12 months)
- Elastic IP attached to a running instance: free; ~$3.65/mo only if left unattached
- EBS gp3 16 GiB: ~$1.30/mo
- Route 53 hosted zone: $0.50/mo

Roughly **$9–12/month** always-on. Stop the instance when idle to cut the compute
cost (note: a stopped instance's Elastic IP then bills ~$3.65/mo since it's unused).

## Security notes worth being able to explain

- SSH uses key-only auth (password login disabled on the image).
- IMDSv2 enforced (hardens against metadata credential theft).
- Encrypted EBS root volume.
- Ports open: 80, 443, and 22. Caddy enforces HTTPS and modern TLS automatically.
- Port 22 is open to `0.0.0.0/0` by choice; tighten to your IP in `ec2.tf` anytime.

### Lab hardening status

Each per-session container already runs with all Linux capabilities dropped,
`no-new-privileges`, memory/CPU/PID caps, and a 30-minute auto-reap; the orchestrator
listens only on localhost. **Still to do before the container holds anything other
than the benign demo page:** the `labnet` Docker network currently allows internet
egress, so switch it to an internal (no-egress) network before introducing the
vulnerable app, and add per-IP rate limiting on `/api/session/start`.

When you add the vulnerable lab later, keep it in **Docker on this box (or a separate
box)** isolated on an internal Docker network, with Caddy reverse-proxying only the
parts you intend to expose — not the vulnerable app directly.
