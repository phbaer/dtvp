import json
from html import escape
from typing import Any, Mapping


def contextual_path(context_path: str, suffix: str) -> str:
    normalized_suffix = suffix if suffix.startswith("/") else f"/{suffix}"
    if not context_path:
        return normalized_suffix
    return f"{context_path}{normalized_suffix}"


def build_startup_status_payload(state: Mapping[str, Any]) -> dict[str, Any]:
    status = str(state.get("status") or "starting")
    message = str(state.get("message") or "DTVP is starting.")
    if status == "failed":
        message = "DTVP startup failed. Check the backend logs."
    return {
        "status": status,
        "ready": status == "ready",
        "message": message,
    }


def build_startup_page_html(
    *,
    state: Mapping[str, Any],
    context_path: str,
) -> str:
    payload = build_startup_status_payload(state)
    status = payload["status"]
    title = "DTVP is ready" if status == "ready" else "DTVP is starting"
    if status == "failed":
        title = "DTVP startup failed"

    status_url = contextual_path(context_path, "/api/startup")
    home_url = contextual_path(context_path, "/")
    escaped_title = escape(title)
    escaped_status = escape(status)
    escaped_message = escape(str(payload["message"]))
    status_url_json = json.dumps(status_url)
    home_url_json = json.dumps(home_url)

    return f"""<!doctype html>
<html lang="en">

<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{escaped_title}</title>
  <style>
    html,
    body {{
      height: 100%;
      margin: 0;
    }}

    body {{
      display: flex;
      align-items: center;
      justify-content: center;
      box-sizing: border-box;
      padding: 24px;
      background:
        radial-gradient(circle at top left, rgba(14, 165, 233, 0.18), transparent 30rem),
        linear-gradient(135deg, #09111f 0%, #111827 48%, #0f172a 100%);
      color: #f8fafc;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}

    main {{
      width: min(100%, 30rem);
      text-align: center;
    }}

    .spinner {{
      width: 3.5rem;
      height: 3.5rem;
      margin: 0 auto 1.5rem;
      border-radius: 999px;
      border: 2px solid rgba(147, 197, 253, 0.28);
      border-top-color: #93c5fd;
      animation: spin 900ms linear infinite;
    }}

    .failed .spinner {{
      animation: none;
      border-color: rgba(251, 191, 36, 0.3);
      border-top-color: #fbbf24;
    }}

    h1 {{
      margin: 0;
      font-size: 1.5rem;
      line-height: 2rem;
      font-weight: 800;
    }}

    p {{
      margin: 1rem 0 0;
      color: #cbd5e1;
      font-size: 0.95rem;
      line-height: 1.6;
    }}

    .hint {{
      color: #94a3b8;
      font-size: 0.8rem;
    }}

    @keyframes spin {{
      to {{
        transform: rotate(360deg);
      }}
    }}
  </style>
</head>

<body>
  <main class="{escaped_status}" role="status" aria-live="polite">
    <div class="spinner" aria-hidden="true"></div>
    <h1 id="startup-title">{escaped_title}</h1>
    <p id="startup-message">{escaped_message}</p>
    <p class="hint">This page will refresh automatically when DTVP is ready.</p>
  </main>
  <script>
    const statusUrl = {status_url_json};
    const homeUrl = {home_url_json};
    const updateStartupState = async () => {{
      try {{
        const response = await fetch(statusUrl, {{ cache: 'no-store' }});
        const payload = await response.json();
        if (payload.ready) {{
          window.location.href = homeUrl;
          return;
        }}
        if (payload.status === 'failed') {{
          document.body.querySelector('main')?.classList.add('failed');
          document.getElementById('startup-title').textContent = 'DTVP startup failed';
        }}
        if (payload.message) {{
          document.getElementById('startup-message').textContent = payload.message;
        }}
      }} catch (error) {{
        // Keep the startup screen visible until the backend can report status.
      }}
    }};

    window.setTimeout(updateStartupState, 300);
    window.setInterval(updateStartupState, 2000);
  </script>
</body>

</html>
"""
