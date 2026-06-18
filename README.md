# Agentic Cybersecurity Demo

A live, on-demand security lab that provisions a fully isolated, two-container
attack/target environment per visitor — built and operated entirely as code.

**Live:** https://oscarlunatech.com

---

## Overview

This project is a self-contained platform for demonstrating the lifecycle of a web
vulnerability — exploration, exploitation, and (on the roadmap) automated remediation —
inside an environment that is safe to expose publicly. A visitor clicks **Start lab**
and the backend spins up two containers wired together on a private network: a
vulnerable web **target** and a **client** shell box to work from. The environment is
tied to the visitor's session and self-destructs after 30 minutes.

The emphasis throughout is on doing it *correctly*: least-privilege access, network
isolation, reproducible infrastructure, and a public attack surface kept deliberately
small even though the lab itself contains intentionally vulnerable software.

## How it works

```
                                  ┌─────────────────────────────────────────────┐
  visitor ──HTTPS──> Caddy ───────┤  /            static landing page            │
                     (TLS,        │  /lab.html    lab control UI (target + shell)│
                      auto-cert)  │  /demo/:id    → session target (iframe)      │
                                  │  /shell/:id   → session client (xterm + exec)│
                                  │  /api         → orchestrator                 │
                                  └───────────────┬─────────────────────────────┘
                                                  │ localhost only
                                          ┌───────▼────────┐
                                          │  orchestrator   │  Node service:
                                          │  (Docker API)   │  create / proxy / reap
                                          └───────┬────────┘
                                                  │  per session
                                   ┌──────────────▼───────────────┐
                                   │  internal network (no egress) │
                                   │   [ client ] ──── [ target ]  │
                                   └───────────────────────────────┘
```

The public web tier (Caddy + the orchestrator) is the only thing reachable from the
internet. The orchestrator binds to localhost and is reached solely through Caddy. Each
lab session lives on its own Docker network created with no route off the host, so a
compromised target cannot reach the internet or other sessions.

## What this project demonstrates

- **Infrastructure as code** — the entire stack (network, instance, DNS, web server,
  container images, orchestrator) is defined in Terraform and reproduced from a single
  `terraform apply`. Nothing is configured by hand on the box.
- **Ephemeral, per-session environments** — containers are created on demand, scoped to
  a session, resource-capped, and automatically reaped on a TTL.
- **Network isolation** — per-session internal Docker networks with verified absence of
  internet egress.
- **Least-privilege everywhere** — scoped IAM, key-only SSH, dropped Linux capabilities,
  `no-new-privileges`, and a localhost-only control plane.
- **Safe handling of intentionally vulnerable software** — the target is isolated such
  that the public footprint stays minimal.

## Tech stack

Terraform · AWS (EC2, Route 53, S3) · Ubuntu · Docker · Node.js · Caddy (Let's Encrypt) ·
xterm.js · WebSockets

## Repository structure

```
terraform/                Infrastructure as code
  ec2.tf                  Instance, security group, key pair, Elastic IP
  route53.tf              DNS records
  variables.tf            Inputs + computed locals (host, Caddyfile, environment)
  data.tf                 Hosted zone + AMI lookups
  outputs.tf              Live URLs, IP, instance id
  providers.tf            AWS provider
  backend.tf              Remote state (S3, versioned, native locking)
  user_data.sh.tftpl      cloud-init: installs and wires up the full stack at boot
site/
  index.html              Static landing page
lab/
  orchestrator/           Node service: session lifecycle, iframe proxy, shell exec
  client-image/           Client (attacker) shell box image
  demo-image/             Default placeholder target image
  frontend/lab.html       Two-pane lab UI (target iframe + client terminal)
```

## Security design

A few decisions worth calling out, since they are the point of the project:

**Minimal public attack surface.** Only Caddy (80/443) and SSH are internet-facing. The
orchestrator listens on `127.0.0.1` and is reachable only via Caddy's reverse proxy. The
state bucket and orchestrator are never directly exposed.

**Hardened containers.** Every session container runs with all Linux capabilities
dropped, `no-new-privileges`, and memory/CPU/PID limits, on a network with no internet
route. Sessions are isolated from one another and torn down on a 30-minute timer.

**Host hardening.** IMDSv2 is enforced (mitigating metadata-based credential theft), the
EBS root volume is encrypted, and SSH is key-only (password auth disabled).

**Least-privilege IAM.** The deploy identity is scoped to only the services it manages.
No long-lived credentials are committed; secrets are kept out of the repository.

**Reproducibility as a control.** Because the box is rebuilt from code, there is no
configuration drift and no hand-tuned state to lose — the repository is the source of
truth.

## Environments

The project runs as two fully isolated environments, selected by Terraform workspace:

- **prod** (`oscarlunatech.com`) — production Let's Encrypt certificate.
- **dev** (`dev.oscarlunatech.com`) — Let's Encrypt **staging** certificate, so the
  environment can be destroyed and rebuilt freely without hitting certificate rate
  limits. Optionally locked to a single source IP.

Each environment has separate state and environment-prefixed resource names, so they
never collide. Switching is a matter of `terraform workspace select`.

## State management

Terraform state is stored remotely in a **versioned, encrypted S3 bucket** with native
state locking. Versioning provides point-in-time recovery of state, and remote storage
decouples state from any single workstation.

## Deployment

Prerequisites: an AWS account, Terraform 1.11+, a registered domain in Route 53, and an
SSH key pair.

```bash
cd terraform
terraform init

# production (default workspace)
terraform apply

# development
terraform workspace new dev
terraform apply
```

On first boot, cloud-init installs Docker, Node.js, and Caddy, builds the container
images, and starts the orchestrator. Caddy obtains a TLS certificate automatically once
DNS resolves. The live URLs are printed as Terraform outputs.

## Roadmap

- **Agentic remediation** — an autonomous agent that detects the target's vulnerability,
  proposes and applies a patch, then re-verifies that the exploit is closed.
- **Documented training target** — swap the placeholder target for an established,
  intentionally vulnerable training application.
- **Per-session subdomain routing** — wildcard-certificate routing for a cleaner
  multi-app iframe experience.
- **Rate limiting** — per-IP throttling on session creation.

## Responsible use

The lab is designed to contain intentionally vulnerable software within an isolated
environment for educational and demonstrative purposes. Any exploitation exercises are
performed only against the project's own disposable target, on a network with no
external reach.
