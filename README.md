# Produce Lookup

A produce code lookup app I built for inventory counts at the retail store where I work, used daily at three stores. It is a single Node.js/Express server (`server.js`) that serves both the API and the mobile-friendly frontend, and it can be installed to a phone's home screen as a PWA.

Data is stored as JSON files in a local `data/` directory, so there is no database to set up.

## Access levels

Everyone signs in on the same login screen with a single password or code. The code you enter determines your role.

| Role | Signs in with | What they can do |
| --- | --- | --- |
| **Staff** | A per-store staff code | Search and view the item list, report a missing item. Lookups are logged against their store. |
| **Manager** | A per-store manager code | Everything staff can do, plus add and edit items, mark items discontinued or reactivated, download a CSV backup, view usage stats and missing-item requests for **their own store only**, and clear their own store's requests. |
| **Admin** | The admin password | Everything managers can do across **all stores**, plus delete items, bulk import, manage stores and their codes, and view the full activity log. |

Each store has its own staff code and manager code. Codes must be unique, the two codes for a store must differ, and neither may match the admin password.

## Features

- **Fast item lookup** by name or code, with recent searches remembered on the device.
- **Offline support**: the app shell is cached by a service worker and the item list is cached locally, with an offline banner when the server can't be reached.
- **Discontinued items** can be flagged and reactivated without deleting them.
- **Missing-item requests**: any signed-in user can report an item that isn't in the list; managers and admins review and clear them.
- **Usage analytics**: lookups per store, most-searched terms, and searches that found nothing (filterable by number of days).
- **Audit log**: every change to the item list and store settings is recorded with who, what, and when (admin only).
- **Bulk import** (admin): paste lines such as `Item name - 12345`, `Item name, 12345` or `Item name 12345`. A leading `D` or `D-` on the code (for example `D-12345`) marks the item as discontinued. Existing items are matched by name and updated.
- **CSV backup** of the whole item list (manager and admin).
- **Store management** (admin): add stores, change names and codes, remove stores.
- **PWA**: web manifest and icons so it installs like a native app.

## Running locally

Requires Node.js 18 or later.

```bash
npm install
ADMIN_PASSWORD=<your-admin-password> SESSION_SECRET=<long-random-string> node server.js
```

Then open <http://localhost:5000>.

## Running with Docker

Build the image using the included `dockerfile` (Node 20 Alpine, listens on port 5000):

```bash
docker build -f dockerfile -t produce-lookup .
```

Run it, mounting a volume so the data survives container restarts:

```bash
docker run -d \
  --name produce-lookup \
  -p 5000:5000 \
  -e ADMIN_PASSWORD=<your-admin-password> \
  -e SESSION_SECRET=<long-random-string> \
  -v produce-data:/app/data \
  produce-lookup
```

Or with Docker Compose (`docker-compose.yml`):

```yaml
services:
  produce:
    build:
      context: .
      dockerfile: dockerfile
    ports:
      - "5000:5000"
    env_file: .env
    volumes:
      - produce-data:/app/data
    restart: unless-stopped

volumes:
  produce-data:
```

> The image does not set `NODE_ENV`. If you pass `-e NODE_ENV=production` (or set it in `.env` with Compose), the session cookie becomes `Secure`, so the app must then be served over HTTPS (for example behind a reverse proxy). The server already sets `trust proxy` for this. For plain-HTTP local testing, leave `NODE_ENV` unset.

## Environment variables

Put these in a `.env` file (or pass them with `-e`). Do not commit real values.

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `ADMIN_PASSWORD` | Yes | None | Password for the admin role. The server exits with an error at startup if it is not set. |
| `SESSION_SECRET` | Recommended | Random value generated on each start | Secret used to sign session cookies. If unset, everyone is logged out whenever the server restarts. |
| `PORT` | No | `5000` | Port the server listens on. |
| `NODE_ENV` | No | unset | Set to `production` to mark session cookies as `Secure` (requires HTTPS). |

Example `.env`:

```env
ADMIN_PASSWORD=<your-admin-password>
SESSION_SECRET=<long-random-string>
PORT=5000
NODE_ENV=production
```

## First-time setup

On first start the server creates the `data/` directory with an empty list of stores. Only the admin can sign in until stores exist, so sign in with the admin password and add your stores, each with its own staff and manager code.

## Data files

Stored in `data/` (mount this as a volume in Docker, and back it up):

| File | Contents |
| --- | --- |
| `items.json` | The item list |
| `config.json` | Stores and their codes |
| `usage.json` | Lookup log (capped at the most recent 20,000 rows) |
| `requests.json` | Missing-item requests (capped at 500) |
| `audit.json` | Change history (capped at 5,000 entries) |

Store codes are kept in `config.json` in plain text, so keep `data/` private.

## How I built it

I'm an assistant manager at a retail store, and I built this app to look up produce codes during inventory counts. It's used daily at three stores.

I run it on a Raspberry Pi in Docker, over Tailscale. I built it with Claude's help, and I made the design decisions myself: three access levels (staff, manager and admin), an audit log of every change, and per-store codes.

Before publishing, I did a security review and removed the default credentials.
