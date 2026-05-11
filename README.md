# Upwind Observer

An AI-powered email threat analysis tool that runs as a **Gmail Add-on**, available on the Google Workspace Marketplace. Every time you open an email, Upwind Observer silently inspects the headers, body, links, and attachments — then produces a scored threat report powered by Claude AI and VirusTotal directly inside your Gmail sidebar.

---

## Features

### Header Analysis
Parses the raw RFC 2822 email headers to extract three industry-standard authentication signals:

- **DMARC** — reads the `Authentication-Results` header to check whether the sending domain passed Domain-based Message Authentication, Reporting & Conformance. A failure is a strong indicator of spoofing.
- **SPF** — reads the `Received-SPF` header to verify the sending mail server was authorised by the domain owner. A failure means the email came from an unexpected source.
- **DKIM** — checks for the presence of a `DKIM-Signature` header. Missing DKIM means the email body was never cryptographically signed by the sending domain.

### URL Analysis
Extracts every `http://` and `https://` link found in the email body using regex, then submits up to **5 URLs** to the VirusTotal API. Each URL is checked against 70+ antivirus and threat intelligence engines. Results show how many engines flagged the link as malicious.

### IP Analysis
Extracts all IPv4 addresses found anywhere in the raw email content using regex. Extracted IPs are surfaced in the **IOCs (Indicators of Compromise)** section of the report so you can investigate them manually or feed them into your own threat intel workflow.

### Attachment Analysis
Each attachment sent by the Gmail Add-on is base64-encoded. The backend decodes the raw bytes and computes a **SHA-256 hash** for every attachment. Those hashes are submitted to VirusTotal's file reputation API — if any antivirus engine has ever seen a file with that exact hash and flagged it as malicious, you will know immediately.

### Claude AI Classification
The plain-text email body is sent to **Claude claude-sonnet-4-6** (Anthropic) with a structured prompt. Claude classifies the email into exactly one of three categories and returns a human-readable explanation:

| Classification | Meaning |
|---|---|
| **Commercial** | Legitimate marketing, newsletters, or promotional emails |
| **Credential Stealing** | Phishing attempts targeting passwords, accounts, or personal data |
| **Malware** | Emails delivering or linking to malicious software |

The AI reasoning is shown in plain English in the "What We Found" section of the report.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Gmail (Browser / Mobile)                                       │
│                                                                 │
│  User opens an email                                            │
│       │                                                         │
│       ▼                                                         │
│  Google Apps Script (Code.gs)          [Marketplace Add-on]    │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  onGmailMessage()                                        │   │
│  │  • Reads raw email, body, attachments via GmailApp       │   │
│  │  • POST /v1/scan  ──────────────────────────────────┐    │   │
│  │                                                     │    │   │
│  │  showReasoning()                                    │    │   │
│  │  • Polls GET /v1/results/{job_id} every 3s ─────┐  │    │   │
│  └─────────────────────────────────────────────────│──│────┘   │
└────────────────────────────────────────────────────│──│────────┘
                                                     │  │
                                              HTTPS (port 443)
                                                     │  │
┌────────────────────────────────────────────────────▼──▼────────┐
│  AWS EC2 (Ubuntu)                                               │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  nginx  (reverse proxy, SSL termination via Let's        │    │
│  │         Encrypt, port 443 → localhost:8000)              │    │
│  └──────────────────────────┬──────────────────────────────┘    │
│                             │                                   │
│  ┌──────────────────────────▼──────────────────────────────┐    │
│  │  FastAPI + Uvicorn  (systemd service, port 8000)         │    │
│  │                                                          │    │
│  │  POST /v1/scan                                           │    │
│  │  ├── auth.py           Validates Bearer token (API_KEY)  │    │
│  │  ├── routers/scan.py   Creates job in MongoDB            │    │
│  │  └── tasks.py          Background analysis pipeline:     │    │
│  │       ├── email_parser.py      Parse RFC 2822 headers    │    │
│  │       ├── security_signals.py  DMARC / SPF / DKIM        │    │
│  │       ├── _extract_iocs()      Regex → URLs + IPs        │    │
│  │       ├── _classify_with_claude() → Anthropic API        │    │
│  │       ├── virustotal.check_url()  → VirusTotal API       │    │
│  │       ├── virustotal.check_hash() → VirusTotal API       │    │
│  │       └── _score()     Compute 0–100 threat score        │    │
│  │                                                          │    │
│  │  GET /v1/results/{job_id}                                │    │
│  │  └── routers/results.py  Read job from MongoDB           │    │
│  └──────────────────────────────────────────────────────────┘    │
└────────────────────────────┬────────────────────────────────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
         MongoDB        Anthropic       VirusTotal
         Atlas          Claude API      API v3
     (job storage)   (classification) (URL + hash scan)
```

---

## Local Development

### Prerequisites
- Python 3.12+
- A [MongoDB Atlas](https://www.mongodb.com/atlas) cluster (free tier works)
- An [Anthropic](https://console.anthropic.com/) API key
- A [VirusTotal](https://www.virustotal.com/gui/join-us) API key

### Run locally

```bash
# 1. Clone the repo
git clone https://github.com/MaximAdamenko/Upwind_Observer_v2.git
cd Upwind_Observer_v2

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Create your .env file (see Configure Environment Variables below)

# 5. Start the server
python3 run.py
```

---

## Production Deployment (AWS EC2)

The production backend runs on an **EC2 instance** behind **nginx** with a **Let's Encrypt SSL certificate**. Google Workspace Marketplace requires HTTPS — a plain IP or HTTP URL will not work.

### Step 1 — Launch an EC2 instance

1. Go to **AWS Console → EC2 → Launch Instance**
2. Choose **Ubuntu Server 22.04 LTS**
3. Instance type: **t3.small** (recommended) or t2.micro (free tier)
4. Security Group — open these inbound ports:

| Port | Protocol | Source | Purpose |
|------|----------|--------|---------|
| 22 | TCP | Your IP | SSH access |
| 80 | TCP | 0.0.0.0/0 | HTTP (Let's Encrypt challenge) |
| 443 | TCP | 0.0.0.0/0 | HTTPS (production traffic) |

5. Create or select a key pair and download the `.pem` file
6. Note the **Public IPv4 address** of your instance

### Step 2 — Point a domain at the instance

You need a domain name for HTTPS (Let's Encrypt cannot issue certs for bare IP addresses).

- Buy a cheap domain (e.g. Namecheap, Google Domains) or use a free subdomain service
- Create an **A record** pointing `api.yourdomain.com` → your EC2 public IP
- Wait for DNS to propagate (usually under 5 minutes)

### Step 3 — Set up the server

SSH into your instance and run the following:

```bash
ssh -i your-key.pem ubuntu@your-ec2-ip

# System packages
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip python3-venv nginx certbot python3-certbot-nginx git

# Clone the repo
git clone https://github.com/MaximAdamenko/Upwind_Observer_v2.git
cd Upwind_Observer_v2

# Virtual environment + dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Create your .env file with production values
nano .env
```

### Step 4 — Configure nginx

Create `/etc/nginx/sites-available/upwind`:

```nginx
server {
    listen 80;
    server_name api.yourdomain.com;

    location / {
        proxy_pass         http://127.0.0.1:8000;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/upwind /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# Issue the SSL certificate
sudo certbot --nginx -d api.yourdomain.com
```

Certbot will automatically edit your nginx config to handle HTTPS and set up auto-renewal.

### Step 5 — Run the backend as a systemd service

Create `/etc/systemd/system/upwind.service`:

```ini
[Unit]
Description=Upwind Observer API
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu/Upwind_Observer_v2
EnvironmentFile=/home/ubuntu/Upwind_Observer_v2/.env
ExecStart=/home/ubuntu/Upwind_Observer_v2/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable upwind
sudo systemctl start upwind

# Verify it's running
sudo systemctl status upwind
curl https://api.yourdomain.com/
# → {"status":"ok","service":"Upwind Observer"}
```

---

## Configure Environment Variables

Create a `.env` file in the project root:

```env
# Shared secret between your backend and Google Apps Script
API_KEY=your-secret-key-here

# Anthropic Claude API key — https://console.anthropic.com/
CLAUDE_API_KEY=sk-ant-...

# Claude model to use for email classification
CLAUDE_MODEL=claude-sonnet-4-6

# VirusTotal API key — https://www.virustotal.com/gui/join-us
VIRUS_TOTAL_KEY=your-vt-key-here

# MongoDB Atlas connection string
MONGODB_URI=mongodb+srv://<user>:<password>@cluster0.xxxxx.mongodb.net/
MONGODB_DB=upwind_observer
```

> **Never commit your `.env` file.** It is already listed in `.gitignore`.

---

## Google Workspace Marketplace Publishing

This is how Upwind Observer goes from a personal script to a publicly installable add-on that any Gmail user can install in one click.

### Step 1 — Create a Google Cloud Project

1. Go to [console.cloud.google.com](https://console.cloud.google.com)
2. Click **New Project** → name it `Upwind Observer`
3. Enable the following APIs:
   - **Gmail API**
   - **Google Workspace Add-ons API**

### Step 2 — Link your Apps Script project

1. Open your Apps Script project at [script.google.com](https://script.google.com)
2. Go to **Project Settings** → **Google Cloud Platform (GCP) Project**
3. Enter your GCP project number and click **Set project**

### Step 3 — Configure the OAuth Consent Screen

1. In GCP Console → **APIs & Services → OAuth consent screen**
2. Set User Type to **External**
3. Fill in:
   - App name: `Upwind Observer`
   - User support email: your email
   - Authorized domain: `yourdomain.com`
   - Developer contact: your email
4. Add scopes:
   - `https://www.googleapis.com/auth/gmail.readonly`
   - `https://www.googleapis.com/auth/gmail.addons.execute`
   - `https://www.googleapis.com/auth/script.external_request`
5. Submit for **verification** (required for public apps — Google review takes a few days)

### Step 4 — Deploy the Add-on

1. In Apps Script → **Deploy → New deployment**
2. Type: **Add-on**
3. Click **Deploy** — copy the **Deployment ID**

### Step 5 — Create the Marketplace listing

1. In GCP Console → **APIs & Services → Google Workspace Marketplace SDK**
2. Enable the SDK, then go to **App Configuration**:
   - App name: `Upwind Observer`
   - Description: *(your description)*
   - App type: **Gmail Add-on**
   - OAuth Client ID: *(from your OAuth setup)*
   - Deployment ID: *(from Step 4)*
3. Go to **Store Listing** → upload screenshots and fill in the listing details
4. Set Visibility to **Public**
5. Click **Submit for review**

> Google's review process typically takes **3–7 business days** for new public add-ons.

Once approved, your add-on will appear on the Marketplace and any Gmail user can install it at [workspace.google.com/marketplace](https://workspace.google.com/marketplace).

---

## Threat Score Calculation

The final threat score is a number from **0 to 100** built by summing contributions from four independent analysis layers.

### Layer 1 — Header Score (max 50 points)

| Signal | Condition | Points |
|--------|-----------|--------|
| DMARC | `fail` | +25 |
| SPF | `fail` | +15 |
| DKIM | absent / `none` | +10 |

DMARC failures are weighted most heavily because they indicate the sending domain is either spoofed or misconfigured — the most common pattern in phishing campaigns.

### Layer 2 — AI Classification Score (max 35 points)

| Claude Classification | Points |
|-----------------------|--------|
| Malware | +35 |
| Credential Stealing | +25 |
| Commercial | +0 |

Claude analyses the full email body and determines intent. Malware delivery is scored higher than credential harvesting because it poses a direct system compromise risk.

### Layer 3 — VirusTotal Score (max 30 points)

Each URL or attachment hash flagged as malicious by at least one VirusTotal engine adds **+15 points**, capped at **30 points total**.

| Malicious VT hits | Points |
|-------------------|--------|
| 0 | +0 |
| 1 | +15 |
| 2+ | +30 |

### Layer 4 — IOC Extraction (informational)

Extracted IPs and URLs are surfaced in the report as **Indicators of Compromise**. They do not directly affect the score but provide actionable intelligence for further investigation.

### Risk Level Mapping

| Score Range | Risk Level |
|-------------|------------|
| 0 – 29 | 🟢 Low |
| 30 – 69 | 🟡 Medium |
| 70 – 100 | 🔴 High |

---

## API Example

### Submit a scan

```http
POST /v1/scan
Authorization: Bearer your-api-key
Content-Type: application/json

{
  "raw_content": "Received: from mail.example.com...\nFrom: sender@example.com\n...",
  "body": "Click here to verify your account: http://suspicious-link.xyz/login",
  "attachments": [
    {
      "filename": "invoice.pdf",
      "content_b64": "JVBERi0xLjQKJcfsj6IKNSAwIG9iag..."
    }
  ]
}
```

**Response:**
```json
{ "job_id": "3f7a1b2c-9e4d-4f8a-b3c1-2d5e6f7a8b9c" }
```

### Poll for results

```http
GET /v1/results/3f7a1b2c-9e4d-4f8a-b3c1-2d5e6f7a8b9c
Authorization: Bearer your-api-key
```

**Response (completed):**
```json
{
  "status": "completed",
  "report": {
    "score": 65,
    "risk_level": "medium",
    "dmarc_status": "fail",
    "spf_status": "pass",
    "dkim_status": "none",
    "ai_classification": "Credential Stealing",
    "ai_reasoning": "This email impersonates a bank and asks the recipient to verify their account credentials via a suspicious external link. The sender domain does not match the claimed institution.",
    "iocs": {
      "ips": ["192.168.1.1"],
      "urls": ["http://suspicious-link.xyz/login"]
    },
    "virustotal_hits": [
      {
        "item": "http://suspicious-link.xyz/login",
        "type": "url",
        "malicious": true,
        "detections": 12
      }
    ],
    "attachment_hashes": [
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ]
  },
  "error": null
}
```

---

## Project Structure

```
Upwind_Observer/
│
├── app/
│   ├── __init__.py
│   ├── auth.py               Bearer token validation
│   ├── config.py             Pydantic settings — reads from .env
│   ├── database.py           Motor async MongoDB client
│   ├── main.py               FastAPI app + CORS setup
│   ├── models.py             MongoDB document factory (job_doc)
│   ├── schemas.py            Pydantic request/response models
│   ├── tasks.py              Core analysis pipeline
│   │
│   ├── routers/
│   │   ├── scan.py           POST /v1/scan
│   │   └── results.py        GET  /v1/results/{job_id}
│   │
│   └── utils/
│       ├── email_parser.py      RFC 2822 raw email parsing
│       ├── security_signals.py  DMARC / SPF / DKIM extraction
│       └── virustotal.py        VirusTotal API client (URLs + hashes)
│
├── google_apps_script/
│   ├── Code.gs               Gmail Add-on logic (submit + poll + render)
│   └── appsscript.json       Add-on manifest + OAuth scopes
│
├── run.py                    Uvicorn entrypoint (local dev)
├── requirements.txt
└── .env                      Secret config (gitignored)
```

---

## Technologies Used

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Add-on runtime | Google Apps Script | Gmail integration, sidebar card UI |
| Marketplace | Google Workspace Marketplace | Public add-on distribution |
| Web framework | FastAPI | Async REST API |
| ASGI server | Uvicorn | Production Python server |
| Reverse proxy | nginx + Let's Encrypt | HTTPS termination on EC2 |
| Cloud hosting | AWS EC2 (Ubuntu) | Always-on backend server |
| Process manager | systemd | Auto-restart on crash/reboot |
| Database | MongoDB Atlas + Motor | Async job storage |
| AI | Anthropic Claude claude-sonnet-4-6 | Email intent classification |
| Threat intel | VirusTotal API v3 | URL and file hash reputation |
| HTTP client | httpx | Async requests to external APIs |
| Config | pydantic-settings | Type-safe environment variable loading |

---

## External Integrations

### Anthropic Claude API
- **Endpoint:** `POST https://api.anthropic.com/v1/messages`
- **What is sent:** Plain-text email body (up to 4000 characters)
- **What is returned:** JSON with `classification` and `reasoning` fields
- **Model used:** `claude-sonnet-4-6`

### VirusTotal API v3
- **URL scan:** `GET https://www.virustotal.com/api/v3/urls/{base64_url_id}`
- **Hash scan:** `GET https://www.virustotal.com/api/v3/files/{sha256}`
- **What is sent:** Base64-encoded URL identifier or SHA-256 file hash
- **What is returned:** `last_analysis_stats` with engine verdict counts
- **Rate limit (free):** 4 requests/min, 500 requests/day

### MongoDB Atlas
- **Driver:** Motor (async PyMongo)
- **Collection:** `jobs`
- **Document schema:**
```json
{
  "_id": "<uuid>",
  "status": "pending | completed | failed",
  "report": { ...full analysis object... },
  "error": null,
  "created_at": "<ISO datetime>",
  "updated_at": "<ISO datetime>"
}
```

---

## Disclaimer

Upwind Observer is an **educational and personal security awareness tool**. It is designed to help individual users understand the potential risk level of emails in their own inbox.

- It does **not** replace enterprise-grade email security gateways (e.g. Proofpoint, Mimecast, Google Workspace Advanced Protection).
- Threat scores are **probabilistic estimates**, not definitive verdicts. A low score does not guarantee an email is safe; a high score does not guarantee it is malicious.
- VirusTotal results reflect the state of their database at the time of the scan. Newly created malicious URLs may not yet be flagged.
- Claude AI classification is based on email content only — it does not access external URLs or execute attachments.
- The tool processes email content by sending it to third-party APIs (Anthropic, VirusTotal). Do **not** use this tool on emails containing classified, legally privileged, or highly sensitive personal information.
- This project is provided as-is, with no warranty. The author accepts no liability for decisions made based on its output.
