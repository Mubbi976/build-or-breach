# BREACH OR BUILD

**Build Secure. Think Like an Attacker. Defend with AI.**

BREACH OR BUILD is a local, interactive developer-training application built around the fictional CareerConnect 2026 university recruitment platform. It is a development and security simulation, not a threat-monitoring dashboard. Simulations use local mock data; submitted code is never executed.

## Architecture

```text
app/
  __init__.py             Application factory and initialization
  config.py               Environment-based configuration
  extensions.py           SQLAlchemy, Login, CSRF, and rate-limit extensions
  models.py               Users, challenges, progress, history, and test records
  routes/                 Authentication, pages, and module API endpoints
  services/               AI analysis, simulation engine, and security checks
  security/               Reusable input/file/auth controls
  templates/              Accessible server-rendered screens
  static/                 Responsive CSS and browser interactions
tests/                    Pytest and Flask test-client coverage
instance/                 Local SQLite database and restricted upload area
```

## Phased implementation

1. Establish the application factory, configuration, and modular project layout.
2. Add relational models, registration/login, password hashing, CSRF, and ownership checks.
3. Build mission progress and interactive STRIDE threat modeling.
4. Add five safe, predefined Secure Code Studio challenges.
5. Integrate OpenAI Responses API analysis behind an isolated service.
6. Add local-only vulnerable/defended attack-and-defense demonstrations.
7. Execute real security checks and persist their results.
8. Derive deployment readiness from executed checks and unresolved findings.
9. Refine responsive, accessible screens and interaction feedback.
10. Run tests and route/simulation smoke checks; document any external setup requirements.

Implementation proceeds in this order so each module builds on the verified data and authentication foundation. Each phase is checked before dependent functionality is layered on top.

## Requirements

- Python 3.11 or newer
- Windows PowerShell, macOS, or Linux
- An OpenAI API key or Google AI Studio Gemini API key for live AI code analysis

The other modules run locally without network access (Monaco Editor and web fonts gracefully fall back if their CDNs are unreachable).

## Windows PowerShell installation

Open PowerShell in the project folder:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

If PowerShell prevents venv activation, allow scripts for the current user, then activate again:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
.\.venv\Scripts\Activate.ps1
```

Edit `.env` and replace `SECRET_KEY` with a random value (for example, generate one with `python -c "import secrets; print(secrets.token_hex(32))"`). Configure one AI provider as described below. Keep `.env` private; it is ignored by Git.

### Choose OpenAI or Gemini

The AI module supports either provider. Set `AI_PROVIDER` in `.env`, add the matching secret key, then restart the app:

**OpenAI (default):**

```dotenv
AI_PROVIDER=openai
OPENAI_API_KEY=your-openai-api-key
OPENAI_MODEL=gpt-4.1-mini
```

**Google Gemini via Google AI Studio:**

```dotenv
AI_PROVIDER=gemini
GEMINI_API_KEY=your-google-ai-studio-key
GEMINI_MODEL=gemini-4-hydrogen
```

Create a Gemini key in [Google AI Studio](https://aistudio.google.com/apikey). The Gemini integration uses Google's documented OpenAI-compatible **Chat Completions** endpoint; the OpenAI integration continues to use the **Responses API**. Choose a Gemini model enabled for your account; see Google's [OpenAI compatibility guide](https://ai.google.dev/gemini-api/docs/openai) and [model list](https://ai.google.dev/gemini-api/docs/models). Configure billing or usage access with the provider as needed. The AI page shows which provider and model the running server loaded, but never returns the secret key to the browser.

## VS Code setup

1. Open the project folder with **File → Open Folder**.
2. Install the Microsoft **Python** extension (Pylance is recommended).
3. Use **Python: Select Interpreter** and choose `.venv\Scripts\python.exe`.
4. Open a new integrated PowerShell terminal, activate the venv if needed, and run `python run.py`.
5. To debug, choose **Run and Debug → Python: Current File** with `run.py` selected. Set `FLASK_DEBUG=1` in `.env` only for local development.

## Run the application

```powershell
.\.venv\Scripts\Activate.ps1
python run.py
```

Open <http://127.0.0.1:5000>. The app creates its SQLite database and seeds five educational challenges at startup. It binds to loopback by default. AI analysis is unavailable until a server-side API key is configured; code stays in the editor when an API call fails.

## Deploy to Vercel

The repository declares the Flask runtime dependencies and `run:app` entrypoint in `pyproject.toml`, and routes all requests through it in `vercel.json`.

In the Vercel project settings, set:

- `SECRET_KEY` to a strong, persistent random value
- `SESSION_COOKIE_SECURE=1`
- `AI_PROVIDER` and the matching provider key if AI analysis is enabled

On Vercel, uploads and the fallback SQLite database use writable `/tmp` storage so the function can start. That storage is temporary and is not suitable for keeping accounts or progress. Set `DATABASE_URL` to a persistent external database to retain application data across function instances and deployments.

### Configure a persistent PostgreSQL database

1. Create a PostgreSQL database with a managed provider such as Neon or Supabase. For serverless hosting, use the provider's pooled connection string when available.
2. In Vercel, open the project and go to **Settings → Environment Variables**.
3. Add `DATABASE_URL` with the provider's PostgreSQL connection string (usually starts with `postgresql://`). Select **Production** and any other environments you deploy, then save.
4. Redeploy the latest commit. The app creates its tables and seeds the training challenges on startup.

Keep the connection string private. Do not commit it or paste it into source files. The project includes the PostgreSQL driver; without `DATABASE_URL`, the app uses temporary SQLite on Vercel and data will not persist.

For HTTPS deployment, set `SESSION_COOKIE_SECURE=1` and configure a strong persistent `SECRET_KEY`. The default `memory://` rate-limit store is for a single local process; use a shared storage backend when deploying multiple workers. Do not expose the built-in development server directly to the internet.

## Create an account and sign in

There are **no built-in, demo, or administrator login credentials**. Create your own account in the application:

1. Start the server with `python run.py` and open <http://127.0.0.1:5000>.
2. Select **Start training** or **Create an account**.
3. Enter a username (3–40 letters, numbers, dots, dashes, or underscores), a valid email address, and a password of at least 12 characters.
4. Select **Create account**. A successful registration redirects to the sign-in page.
5. Sign in with the **same email address and password** you just registered. Passwords are case-sensitive; the application stores a secure password hash, not the original password.
6. After signing in, use the sidebar to open modules, return to **Mission Control**, visit your **Developer profile**, or select **Sign out** when finished.

If you have already registered, continue to **Sign in** using that account; do not register again unless you want another account. Accounts and progress are stored in the local SQLite database at `instance/careerconnect.db`, so they remain available after restarting the app as long as that database is kept and the `SECRET_KEY` remains stable. No password-reset flow is currently provided. If you forget a local training password, create another account with a different email address.

## Application walkthrough

Start at **Mission Control**. It introduces the fictional CareerConnect 2026 project, summarizes module and challenge progress, and links to each training activity.

1. **Threat Modeling Lab:** select a browser, API, or database component; choose one of its STRIDE threats and a defensive control; submit the decision to get feedback.
2. **Secure Code Studio:** review the vulnerable and secure examples for each of the five challenges. Choose which implementation you would ship to see feedback and save the attempt.
3. **AI Security Engineer (optional):** paste or type a code snippet, then select **Analyze code**. Choose OpenAI or Gemini using `AI_PROVIDER` and the matching server-side API key in `.env`, then restart the app. Provider account access is required; there is no shared application key or provided credential. If the key is not configured or the provider call fails, the app explains the error and leaves your code in the editor.
4. **Attack & Defense Arena:** choose one of the four fictional scenarios and run the vulnerable version. Then enable the defense and rerun to compare results. These are local mock simulations, not real attacks.
5. **Security Testing Lab:** select **Run all checks** to execute the application's six security checks. The page shows the actual PASS/FAIL results from that run.
6. **Deployment Gate:** review the latest results and any open review items. Resolve review items here; run missing or failed checks again in the Testing Lab. The decision updates from the evidence: a critical failure or unresolved critical finding is **BLOCKED**; missing/failed checks or other open items require **NEEDS REVIEW**; all passing required checks and no open items allow **READY**.
7. **Developer profile:** view your challenge, AI analysis, and simulation history. Records are scoped to your account. **Restart mission** on Mission Control clears challenge attempts and module progress, but preserves analysis, simulation, and test history.

Use the sidebar to move between modules, and use **← Mission Control** within a module to return to the project overview. State-changing forms and actions include CSRF protection. Use fictional code and data in this educational application; code submitted to the AI module is sent to the configured OpenAI service when you explicitly request an analysis.

## Tests

```powershell
python -m pytest -q
```

The security lab runs actual focused checks, including a live Flask-Limiter request sequence. These checks cover selected controls and are not a complete penetration test or deployment certification.

## Module notes

- **Threat Modeling Lab:** interactive browser/API/database path, STRIDE threat selection, and control evaluation.
- **Secure Code Studio:** five seeded challenges; predefined code comparisons and server-recorded decisions. Submitted code is not executed.
- **AI Security Engineer:** server-side provider keys; OpenAI Responses API or Gemini's OpenAI-compatible Chat Completions API; JSON parsing and result validation. AI output is explicitly advisory.
- **Attack & Defense Arena:** deterministic mock scenarios with fictional data; no real targets, files, password guessing, or SQL are used.
- **Security Testing Lab:** executes parameterized-query, password-hash, ownership, file-policy, real rate-limit, and session checks.
- **Deployment Gate:** uses each user's latest result for all six required checks; a critical failed test or unresolved critical finding blocks, any missing/failed check or other open review item needs review, and all passing checks with no open items permits READY.
- **User Profile:** history is filtered by the authenticated user. Mission restart clears challenge attempts and module progress while preserving test, AI, and simulation history.

## Troubleshooting

- **`python` or `py` is not found:** install Python 3.11+ and reopen the terminal; on Windows, enable the Python launcher or add Python to PATH.
- **PowerShell says scripts are disabled:** run the `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` command above, or invoke the venv interpreter directly as `.\.venv\Scripts\python.exe`.
- **Import/module errors:** activate the project venv and run `python -m pip install -r requirements.txt`.
- **Login/CSRF failures after changing `.env`:** ensure `SECRET_KEY` is a nonempty stable value, restart the app, and reload the sign-in page so its CSRF token is refreshed.
- **AI review says it is not configured:** check `AI_PROVIDER` and set its matching key (`OPENAI_API_KEY` or `GEMINI_API_KEY`) in `.env`, then restart the app. Never put a key in browser JavaScript or commit `.env`.
- **AI review reports a provider error:** the AI page's configuration indicator shows which provider and model the running server loaded, without exposing its key. Restart with `Ctrl+C` and `python run.py` after editing `.env`. Check that the selected provider key is active, the model is available to that account, and provider billing/usage limits and network access permit requests. The page distinguishes common authentication, access, quota, network, and request-format errors. Code stays in the editor and no analysis history is written for a failed call.
- **SQLite database locked or stale development data:** stop other local app processes before testing. The normal database is `instance/careerconnect.db`; tests use isolated in-memory databases.
- **Monaco does not load:** the editor falls back to its accessible code textarea; external CDN access is optional.
- **Rate-limit results are unexpected:** the default limiter store is in-process memory. Restarting the process clears that local store; a multi-worker deployment needs shared storage.

## Security boundaries

This is an educational local application, not a production recruitment system. Use fictional data only. Passwords are hashed; CSRF, authentication, rate limiting, server-side authorization, file-policy validation, and secure cookie attributes are implemented. The upload policy is exercised as a validation control; the simulation does not write or execute a user-uploaded file. AI analysis is an external API call only when explicitly requested and configured.
