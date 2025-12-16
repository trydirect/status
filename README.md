# Status Panel (Beacon)

Server stack health application with UI.


## Build

```bash
cargo build --release
```

## Run

Foreground daemon (default without subcommands):

```bash
./target/release/status --config config.json
```

Daemon mode (background):

```bash
./target/release/status --daemon --config config.json
```

Local API server (API-only mode):

```bash
./target/release/status serve --port 8080
```

Local API server with UI (serves HTML templates):

```bash
./target/release/status serve --port 8080 --with-ui
```

Then open your browser to `http://localhost:8080/login` to access the web interface.

Docker operations (requires `--features docker`):

```bash
cargo run --features docker --bin status -- containers
cargo run --features docker --bin status -- restart status
```

## Features

- **API-only mode**: Returns JSON responses for programmatic access
- **UI mode** (`--with-ui`): Serves HTML templates from `templates/` directory with static files from `static/`
- Docker container management (list, restart, stop, pause)
- Session-based authentication
- Health check endpoint

## Templates

The UI uses Tera templating engine (similar to Jinja2). Templates are located in:
- `templates/` - HTML templates (login.html, index.html, error.html)
- `static/` - CSS, JavaScript, and other static assets

## Notes

- Reads `config.json` and normalizes `apps_info` to structured items.
- Subsystems marked with `@todo` will be implemented per `.ai/GOAL.md`.
