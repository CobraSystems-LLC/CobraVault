# CobraVault

Single-file offline password manager.

## Requirements

- Python 3.10+
- `cryptography`

Install the dependency:

```bash
python3 -m pip install cryptography
```

## Run

```bash
python3 cobravault.py
```

The encrypted vault file is stored next to the script as `vault.enc`.

## Useful options

- `--vault /path/to/vault.enc` to use a different encrypted vault file
- `--clipboard-timeout 60` to change the default clipboard clear timer
- `--generate-password --length 24` to print a generated password without opening the interactive vault UI
- `--generate-password --length 24 --no-symbols` to generate a password without punctuation

`--generate-password` works without `cryptography`; the full vault UI requires it.