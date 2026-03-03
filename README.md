# OpenMRS Dependency Vulnerability Dashboard

Small frontend dashboard for the GSoC starter challenge.

It reads dependency vulnerability reports for 3 OpenMRS repositories and shows them in a collapsible report view.

## Data sources

By default, the app can use both:

- Local static files in `./data`
- GitHub Actions artifacts (latest successful runs on `main`, fallback `master`)

If live fetch fails (rate limits, missing artifacts, network issues), it falls back to local JSON automatically.

## What this implementation covers

- Dynamic rendering for:
  - `openmrs-core.json`
  - `openmrs-module-billing.json`
  - `openmrs-module-idgen.json`
- Collapsible repository sections
- Collapsible dependency rows
- CVE detail table
- Severity pills
- Missing data fallback to `-`

## Logic implemented

- CVEs sorted by:
  - score desc
  - severity desc
  - CVE id A-Z
- Dependencies sorted by:
  - severity desc
  - highest CVE score desc
  - name A-Z
- Repositories sorted by:
  - severity desc
  - highest CVE score desc
  - name A-Z
- Dependency severity: based on highest-score CVE
- Repository severity: based on highest-score CVE in repo
- Fix version: highest `fixedIn` only when all CVEs for that dependency have one
- Score handling: read only from explicit numeric report fields (no inference from description text)

## Run locally

```bash
python3 -m http.server 8080
```

Open `http://localhost:8080`.

## Optional GitHub token

If you hit GitHub API rate limits, set this before `app.js` loads:

```html
<script>
  window.OPENMRS_GITHUB_TOKEN = "your_github_token";
</script>
```

## Project layout

- `index.html` - page structure
- `styles.css` - styling
- `app.js` - app bootstrap and UI state
- `constants.js` - shared constants/config
- `loader.js` - live/static loading logic
- `transform.js` - normalization, aggregation, sorting
- `render.js` - HTML rendering
