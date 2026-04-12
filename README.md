---
title: CTF Vulnerability Sandbox
emoji: 🛡️
colorFrom: blue
colorTo: red
sdk: docker
app_port: 8000
tags:
  - openenv
  - security
  - benchmark
---

# OpenEnv CTF Vulnerability Sandbox

This repository packages a **10-task web-security agent benchmark** for OpenEnv. Each episode launches an isolated vulnerable Node.js application, exposes a tool-based interface for source inspection and HTTP interaction, and grades the agent with deterministic rewards in **`[0.0, 1.0]`**.

The benchmark is designed to feel closer to a real application-security workflow than a toy CTF:
- agents read source files and configuration rather than receiving exploit strings
- exploit chains span authentication, access-control, business-logic, SSRF, XSS, and unsafe code execution
- graders award **partial, deterministic milestone credit** for meaningful progress, not just binary flag capture
- noisy probing is tracked through `noise_penalty`, `precision_bonus`, and `detection_risk`

## Benchmark surface

The public tool contract is intentionally stable and judge-friendly:
- `list_source_files`
- `view_source`
- `http_request`
- `submit_flag`
- `get_task_info`
- `start_task`

The main benchmark trio used by `inference.py` remains:
- `sqli_login`
- `idor_privesc`
- `payment_logic`

The full local benchmark exposes 10 tasks:

| Task | Difficulty | Theme |
| --- | --- | --- |
| `sqli_login` | easy | login bypass via SQL injection |
| `sqli_union` | medium | UNION-based data extraction |
| `idor_privesc` | medium | IDOR plus mass-assignment privilege escalation |
| `payment_logic` | hard | negative-quantity checkout logic flaw |
| `command_injection` | medium | command execution in admin export |
| `jwt_forgery` | medium | forged admin JWT using weak secret |
| `ssrf` | hard | authenticated SSRF with internal pivot ticket |
| `xss_stored` | medium | stored XSS in product reviews |
| `path_traversal` | medium | file read outside uploads directory |
| `deserialization` | hard | authenticated unsafe import with stored job retrieval |

## Reward design

Scoring is deterministic and bounded:
- every step reward is in **`[0.0, 1.0]`**
- final episode score is in **`[0.0, 1.0]`**
- graders only award milestones when task-specific evidence is present
- summaries expose:
  - `final_score`
  - `milestones_achieved`
  - `milestones_missed`
  - `precision_bonus`
  - `noise_penalty`
  - `detection_risk`

This keeps the environment faithful to the hackathon grading expectations while still offering meaningful intermediate learning signal.

## Project layout

```text
CTF-RL/
├── Dockerfile
├── openenv.yaml
├── inference.py
├── test_integration.py
├── models.py
├── server/
│   ├── app.py
│   ├── ctf_environment.py
│   ├── reward.py
│   ├── graders.py
│   ├── tasks/
│   └── vulnerable_app/
└── client.py
```

## Local setup

Prerequisites:
- Python 3.10+
- Node.js 18+
- `uv`

Install Python dependencies:

```bash
uv sync
```

Run the OpenEnv server locally:

```bash
uv run server
```

The environment serves the OpenEnv/FastAPI app on port `8000`.

## Integration validation

Run the end-to-end suite against the local server:

```bash
uv run python test_integration.py
```

The suite covers:
- all 10 exposed tasks
- partial reward progression
- negative-credit checks for near misses
- deterministic reward traces
- reset isolation
- score-bound invariants

Additional validation commands:

```bash
openenv validate
uv run python -m py_compile __init__.py inference.py test_integration.py
docker build -t ctf-rl-local .
```

## Inference contract

`inference.py` preserves the Phase 1/2 submission contract:

Required environment variables:
- `API_BASE_URL`
- `MODEL_NAME`
- `HF_TOKEN`

Optional environment variables:
- `LOCAL_IMAGE_NAME`
- `ENV_URL`

The script configures the OpenAI-compatible client from those variables and writes only structured log lines on stdout:
- `[START]`
- `[STEP]`
- `[END]`

Example local run:

```bash
set API_BASE_URL=https://your-openai-compatible-endpoint
set MODEL_NAME=your-model-name
set HF_TOKEN=your-api-key
set ENV_URL=http://localhost:8000
uv run python inference.py
```

## Hugging Face Space deployment

The benchmark is packaged for a Docker Space. A validated deployment is available at:
- Space repo: [swar16/ctf-rl](https://huggingface.co/spaces/swar16/ctf-rl)
- Live URL: [https://swar16-ctf-rl.hf.space](https://swar16-ctf-rl.hf.space)

To deploy your own copy:

```bash
uv run hf repos create <username>/ctf-rl --type space --space-sdk docker --public
openenv push --repo-id <username>/ctf-rl
```

Judge-facing checks to keep green:
- `POST /reset` returns `200`
- `/schema` returns `200`
- repo-root `Dockerfile` builds successfully
- `openenv validate` passes

## Submission notes

This repository keeps the judge-facing contracts stable:
- `openenv.yaml` remains unchanged
- Docker still serves the app on port `8000`
- the benchmark trio in `inference.py` is unchanged
- all public tool names and response semantics remain additive-compatible
- partial reward reporting now reflects the environment’s true milestone grading

If you want to extend the benchmark further after submission, the safest next step is to add new tasks or stronger hard-mode variants without changing the existing tool or scoring contract.
