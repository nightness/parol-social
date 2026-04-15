# ParolNet Distribution Server

Static HTML landing pages that serve as the distribution point for the ParolNet PWA. The pages are intentionally disguised as a calculator app listing to appear innocuous.

## Files

- **`index.html`** — Full app-store-style landing page with app info, install button, instructions, and privacy note.
- **`install.html`** — Minimal version with just icon, name, and install button. Use this for direct distribution links.
- **`nginx.conf`** — Nginx configuration with security headers, WASM MIME types, Service Worker support, and gzip compression.

## Hosting with Docker (Recommended)

A `Dockerfile` and `docker-compose.yml` are provided at the project root.

### Using Docker Compose

```bash
# Build and run
docker compose up -d

# View at http://localhost:1411
# Stop
docker compose down
```

### Using Docker directly

```bash
docker build -t parolnet .
docker run -d -p 1411:80 parolnet
```

The Docker image uses `nginx:alpine` (~5 MB) and serves both the distribution landing page (at `/`) and the PWA (at `/pwa/`).

## Alternative Hosting Options

These are plain static HTML files with zero dependencies. Any static file server works.

- **Nginx / Apache / Caddy** — Drop the files in your document root. Make sure WASM files are served with the `application/wasm` MIME type (the provided `nginx.conf` handles this).
- **CDN** — Cloudflare Pages, Netlify, GitHub Pages, Vercel. Push and deploy.
- **S3 / R2** — Upload as a static website.
- **IPFS** — Pin the directory for censorship-resistant hosting.
- **Tor Hidden Service** — Host as a `.onion` site for anonymous access.

## Important Notes

- **WASM MIME type** — WASM files must be served with `Content-Type: application/wasm`. The included `nginx.conf` handles this. If using a different server, configure it accordingly.
- **Service Worker requires HTTPS** — The Service Worker will only register over HTTPS or on `localhost`. For production deployments, use HTTPS. For local development, `http://localhost:1411` works fine.

## Directory Structure

The Docker setup serves files at these paths:

```
/                  → server/index.html  (distribution landing page)
/install.html      → server/install.html (minimal install page)
/pwa/              → pwa/               (the PWA app itself)
/pwa/index.html    → pwa/index.html     (app shell)
/pwa/pkg/          → pwa/pkg/           (WASM module + JS bindings)
```

## Customization

To update the version or release date, edit the static values in `index.html`:

- **Version** — Search for `1.0.0`
- **Release date** — Search for `Apr 2026`
- **App size** — Search for `~2 MB`

## Design Decisions

- **No JavaScript frameworks** — Pure static HTML with inline CSS.
- **No external dependencies** — Static assets can be opened from many environments. Full PWA behavior, including Service Worker install and offline caching, requires HTTPS or `localhost`; `file://` is limited-use only.
- **Innocuous appearance** — The page presents as a calculator utility download. No references to encryption, messaging, security, or ParolNet.
- **Mobile-first** — Responsive layout, max-width 480px, looks good on phones.
