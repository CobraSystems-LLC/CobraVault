#!/usr/bin/env python3
"""CobraVault - a single-file offline password manager."""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
import textwrap
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:  # pragma: no cover - exercised manually in production
    AESGCM = None
    PBKDF2HMAC = None
    hashes = None


APP_NAME = "CobraVault"
VAULT_FILENAME = "vault.enc"
BACKUP_SUFFIX = ".enc"
FORMAT_VERSION = 1
PBKDF2_ITERATIONS = 600_000
AES_KEY_BYTES = 32
SALT_BYTES = 16
NONCE_BYTES = 12
AUTO_LOCK_SECONDS = 300
DEFAULT_CLIPBOARD_TIMEOUT = 45
MIN_MASTER_PASSWORD_LENGTH = 12


class VaultError(Exception):
    """Base application error."""


class DependencyError(VaultError):
    """Raised when cryptography is unavailable."""


class AuthenticationError(VaultError):
    """Raised when unlocking fails."""


class ClipboardError(VaultError):
    """Raised when no clipboard backend works."""


class AutoLockError(VaultError):
    """Raised when inactivity timeout expires."""


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def prompt(message: str) -> str:
    return input(message).strip()


def prompt_non_empty(message: str) -> str:
    while True:
        value = prompt(message)
        if value:
            return value
        print("Value cannot be empty.")


def prompt_int(message: str, default: int, minimum: int, maximum: int) -> int:
    while True:
        raw = prompt(f"{message} [{default}]: ")
        if not raw:
            return default
        try:
            value = int(raw)
        except ValueError:
            print("Please enter a valid number.")
            continue
        if minimum <= value <= maximum:
            return value
        print(f"Please choose a value between {minimum} and {maximum}.")


def confirm(message: str, default: bool = False) -> bool:
    suffix = "Y/n" if default else "y/N"
    while True:
        raw = prompt(f"{message} [{suffix}]: ").lower()
        if not raw:
            return default
        if raw in {"y", "yes"}:
            return True
        if raw in {"n", "no"}:
            return False
        print("Please answer yes or no.")


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def mask_secret(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def print_header(title: str) -> None:
    print(f"\n=== {title} ===")


def best_effort_wipe(buffer: bytearray | None) -> None:
    if buffer is None:
        return
    for index in range(len(buffer)):
        buffer[index] = 0


def ensure_dependencies() -> None:
    if AESGCM and PBKDF2HMAC and hashes:
        return
    raise DependencyError(
        "Missing dependency: cryptography\n"
        "Install it with:\n"
        "  Windows:    py -m pip install cryptography\n"
        "  Chromebook: python3 -m pip install cryptography"
    )


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def derive_key(master_secret: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    # The master password is never written to disk. We derive a fresh 256-bit
    # AES key from the password and a random per-vault salt each time we need it.
    secret_bytes = bytearray(master_secret.encode("utf-8"))
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_BYTES,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(bytes(secret_bytes))
    finally:
        best_effort_wipe(secret_bytes)


def encrypt_payload(
    data: dict[str, Any],
    key_material: bytearray,
    salt: bytes,
    iterations: int = PBKDF2_ITERATIONS,
) -> dict[str, Any]:
    nonce = os.urandom(NONCE_BYTES)
    plaintext = bytearray(json.dumps(data, indent=2, sort_keys=True).encode("utf-8"))
    try:
        # AES-GCM provides both encryption and integrity protection for the
        # entire JSON payload, so tampering is detected during unlock.
        ciphertext = AESGCM(bytes(key_material)).encrypt(nonce, bytes(plaintext), None)
    finally:
        best_effort_wipe(plaintext)
    return {
        "format": APP_NAME,
        "version": FORMAT_VERSION,
        "kdf": {
            "name": "PBKDF2-HMAC-SHA256",
            "iterations": iterations,
            "salt": b64encode(salt),
        },
        "cipher": {
            "name": "AES-256-GCM",
            "nonce": b64encode(nonce),
            "ciphertext": b64encode(ciphertext),
        },
    }


def payload_kdf_metadata(payload: dict[str, Any]) -> tuple[int, bytes]:
    try:
        if payload["format"] != APP_NAME or payload["version"] != FORMAT_VERSION:
            raise VaultError("Unsupported vault format.")
        iterations = int(payload["kdf"]["iterations"])
        salt = b64decode(payload["kdf"]["salt"])
    except (KeyError, TypeError, ValueError) as exc:
        raise VaultError("Vault file is corrupted or incomplete.") from exc
    return iterations, salt


def decrypt_payload(payload: dict[str, Any], master_secret: str) -> dict[str, Any]:
    iterations, salt = payload_kdf_metadata(payload)
    try:
        nonce = b64decode(payload["cipher"]["nonce"])
        ciphertext = b64decode(payload["cipher"]["ciphertext"])
    except (KeyError, TypeError, ValueError) as exc:
        raise VaultError("Vault file is corrupted or incomplete.") from exc

    key = bytearray(derive_key(master_secret, salt, iterations=iterations))
    try:
        plaintext = bytearray(AESGCM(bytes(key)).decrypt(nonce, ciphertext, None))
        return json.loads(plaintext.decode("utf-8"))
    except Exception as exc:  # cryptography exceptions vary by version
        raise AuthenticationError("Incorrect master password or corrupted vault data.") from exc
    finally:
        best_effort_wipe(key)
        if "plaintext" in locals():
            best_effort_wipe(plaintext)


def password_strength(password: str) -> tuple[str, int]:
    score = 0
    checks = [
        len(password) >= 12,
        any(ch.islower() for ch in password),
        any(ch.isupper() for ch in password),
        any(ch.isdigit() for ch in password),
        any(ch in string.punctuation for ch in password),
        len(password) >= 16,
    ]
    score = sum(checks)
    if score <= 2:
        return ("Weak", score)
    if score <= 4:
        return ("Fair", score)
    if score == 5:
        return ("Good", score)
    return ("Strong", score)


def generate_password(
    length: int = 20,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> str:
    pools: list[str] = []
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.?/|")
    if not pools:
        raise VaultError("Select at least one character group.")

    ambiguous = {"0", "O", "o", "1", "l", "I"}
    if exclude_ambiguous:
        pools = ["".join(ch for ch in pool if ch not in ambiguous) for pool in pools]
        pools = [pool for pool in pools if pool]
        if not pools:
            raise VaultError("No characters available after excluding ambiguous characters.")

    all_chars = "".join(pools)
    if length < len(pools):
        raise VaultError(f"Length must be at least {len(pools)} to include all selected groups.")

    rng = secrets.SystemRandom()
    password_chars = [rng.choice(pool) for pool in pools]
    password_chars.extend(rng.choice(all_chars) for _ in range(length - len(password_chars)))
    rng.shuffle(password_chars)
    return "".join(password_chars)


def summarize_entry(entry: dict[str, Any]) -> str:
    return f"{entry['title']} | {entry['username']} | {entry.get('url') or '-'}"


class ClipboardManager:
    """Cross-platform clipboard helper with best-effort timeout clearing."""

    def __init__(self, script_path: Path):
        self.script_path = script_path

    def _tk_command(self, action: str, text: str = "") -> subprocess.CompletedProcess[str]:
        code = textwrap.dedent(
            """
            import sys
            import tkinter as tk

            action = sys.argv[1]
            text = sys.argv[2] if len(sys.argv) > 2 else ""
            root = tk.Tk()
            root.withdraw()
            if action == "set":
                root.clipboard_clear()
                root.clipboard_append(text)
                root.update()
            elif action == "get":
                try:
                    sys.stdout.write(root.clipboard_get())
                except tk.TclError:
                    pass
            elif action == "clear":
                root.clipboard_clear()
                root.update()
            root.destroy()
            """
        ).strip()
        return subprocess.run(
            [sys.executable, "-c", code, action, text],
            capture_output=True,
            text=True,
            check=True,
        )

    def _try_set(self, text: str) -> None:
        errors: list[str] = []
        methods = [
            ("tkinter", lambda: self._tk_command("set", text)),
        ]
        if sys.platform.startswith("win"):
            methods.extend(
                [
                    (
                        "clip",
                        lambda: subprocess.run(
                            ["clip"],
                            input=text,
                            capture_output=True,
                            text=True,
                            check=True,
                        ),
                    ),
                ]
            )
        else:
            methods.extend(
                [
                    (
                        "wl-copy",
                        lambda: subprocess.run(
                            ["wl-copy"],
                            input=text,
                            capture_output=True,
                            text=True,
                            check=True,
                        ),
                    ),
                    (
                        "xclip",
                        lambda: subprocess.run(
                            ["xclip", "-selection", "clipboard"],
                            input=text,
                            capture_output=True,
                            text=True,
                            check=True,
                        ),
                    ),
                    (
                        "xsel",
                        lambda: subprocess.run(
                            ["xsel", "--clipboard", "--input"],
                            input=text,
                            capture_output=True,
                            text=True,
                            check=True,
                        ),
                    ),
                ]
            )
        for name, method in methods:
            try:
                method()
                return
            except Exception as exc:
                errors.append(f"{name}: {exc}")
        raise ClipboardError(
            "Unable to access the clipboard. On Linux/ChromeOS install tkinter, wl-clipboard, xclip, or xsel.\n"
            + "\n".join(errors)
        )

    def _try_clear(self) -> None:
        methods = [
            lambda: self._tk_command("clear"),
        ]
        if sys.platform.startswith("win"):
            methods.append(
                lambda: subprocess.run(
                    ["clip"],
                    input="",
                    capture_output=True,
                    text=True,
                    check=True,
                )
            )
        else:
            methods.extend(
                [
                    lambda: subprocess.run(
                        ["wl-copy"],
                        input="",
                        capture_output=True,
                        text=True,
                        check=True,
                    ),
                    lambda: subprocess.run(
                        ["xclip", "-selection", "clipboard"],
                        input="",
                        capture_output=True,
                        text=True,
                        check=True,
                    ),
                    lambda: subprocess.run(
                        ["xsel", "--clipboard", "--input"],
                        input="",
                        capture_output=True,
                        text=True,
                        check=True,
                    ),
                ]
            )
        for method in methods:
            try:
                method()
                return
            except Exception:
                continue
        raise ClipboardError("Copied password, but could not clear the clipboard later.")

    def copy_with_timeout(self, text: str, timeout_seconds: int = DEFAULT_CLIPBOARD_TIMEOUT) -> None:
        self._try_set(text)
        popen_kwargs: dict[str, Any] = {
            "args": [
                sys.executable,
                str(self.script_path),
                "--clear-clipboard",
                "--timeout",
                str(timeout_seconds),
            ],
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        if os.name == "nt":
            popen_kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
        else:
            popen_kwargs["start_new_session"] = True
        subprocess.Popen(**popen_kwargs)

    def clear_after_timeout(self, timeout_seconds: int) -> None:
        time.sleep(timeout_seconds)
        self._try_clear()


@dataclass
class VaultStore:
    vault_path: Path
    key_material: bytearray
    salt: bytes
    iterations: int
    data: dict[str, Any]

    @classmethod
    def initialize_new(cls, vault_path: Path, master_secret: str) -> "VaultStore":
        salt = os.urandom(SALT_BYTES)
        key_material = bytearray(derive_key(master_secret, salt))
        data = {
            "entries": [],
            "meta": {
                "created_at": now_iso(),
                "updated_at": now_iso(),
            },
        }
        store = cls(
            vault_path=vault_path,
            key_material=key_material,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            data=data,
        )
        store.save()
        return store

    @classmethod
    def unlock(cls, vault_path: Path, master_secret: str) -> "VaultStore":
        try:
            payload = json.loads(vault_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise VaultError("Vault file was not found.") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise VaultError("Vault file could not be read.") from exc
        data = decrypt_payload(payload, master_secret)
        if not isinstance(data, dict) or "entries" not in data:
            raise VaultError("Vault content is invalid.")
        data.setdefault("meta", {})
        iterations, salt = payload_kdf_metadata(payload)
        key_material = bytearray(derive_key(master_secret, salt, iterations=iterations))
        return cls(
            vault_path=vault_path,
            key_material=key_material,
            salt=salt,
            iterations=iterations,
            data=data,
        )

    def _write_payload(self, data: dict[str, Any]) -> None:
        payload = encrypt_payload(data, self.key_material, self.salt, self.iterations)
        serialized = json.dumps(payload, indent=2)
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=self.vault_path.parent,
                prefix=f".{self.vault_path.name}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                handle.write(serialized)
                handle.flush()
                os.fsync(handle.fileno())
                temp_path = Path(handle.name)
            os.replace(temp_path, self.vault_path)
        except OSError as exc:
            raise VaultError("Vault file could not be written.") from exc
        finally:
            if temp_path and temp_path.exists():
                temp_path.unlink(missing_ok=True)

    def save(self) -> None:
        self.data.setdefault("meta", {})
        self.data["meta"]["updated_at"] = now_iso()
        self._write_payload(self.data)

    def list_entries(self) -> list[dict[str, Any]]:
        entries = self.data.get("entries", [])
        return sorted(entries, key=lambda item: item["title"].lower())

    def add_entry(self, entry: dict[str, Any]) -> None:
        self.data["entries"].append(entry)
        self.save()

    def update_entry(self, entry_id: str, updates: dict[str, Any]) -> bool:
        for entry in self.data["entries"]:
            if entry["id"] == entry_id:
                entry.update(updates)
                entry["updated_at"] = now_iso()
                self.save()
                return True
        return False

    def delete_entry(self, entry_id: str) -> bool:
        original_count = len(self.data["entries"])
        self.data["entries"] = [entry for entry in self.data["entries"] if entry["id"] != entry_id]
        if len(self.data["entries"]) == original_count:
            return False
        self.save()
        return True

    def find_by_id(self, entry_id: str) -> dict[str, Any] | None:
        for entry in self.data["entries"]:
            if entry["id"] == entry_id:
                return entry
        return None

    def search(self, term: str) -> list[dict[str, Any]]:
        needle = term.lower()
        results = []
        for entry in self.list_entries():
            haystack = " ".join(
                [
                    entry.get("title", ""),
                    entry.get("username", ""),
                    entry.get("url", ""),
                    entry.get("notes", ""),
                ]
            ).lower()
            if needle in haystack:
                results.append(entry)
        return results

    def export_backup(self, target_path: Path) -> None:
        if target_path.resolve() == self.vault_path.resolve():
            raise VaultError("Backup path must be different from the main vault file.")
        target_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(self.vault_path, target_path)
        except OSError as exc:
            raise VaultError("Backup file could not be written.") from exc

    def import_backup(self, source_path: Path, backup_password: str) -> None:
        try:
            payload = json.loads(source_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise VaultError("Backup file was not found.") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise VaultError("Backup file could not be read.") from exc
        imported_data = decrypt_payload(payload, backup_password)
        if not isinstance(imported_data, dict) or "entries" not in imported_data:
            raise VaultError("Backup content is invalid.")
        imported_data.setdefault("meta", {})
        imported_data["meta"]["updated_at"] = now_iso()
        self._write_payload(imported_data)
        self.data = imported_data

    def change_master_password(self, new_master_password: str) -> None:
        previous_key = bytearray(self.key_material)
        previous_salt = self.salt
        new_salt = os.urandom(SALT_BYTES)
        new_key = bytearray(derive_key(new_master_password, new_salt, iterations=self.iterations))
        self.key_material = new_key
        self.salt = new_salt
        try:
            self.save()
        except Exception:
            best_effort_wipe(new_key)
            self.key_material = previous_key
            self.salt = previous_salt
            raise
        best_effort_wipe(previous_key)


class CobraVaultCLI:
    def __init__(self, vault_path: Path, clipboard_timeout: int):
        self.vault_path = vault_path
        self.clipboard_timeout = clipboard_timeout
        self.clipboard = ClipboardManager(script_path=Path(__file__).resolve())
        self.store: VaultStore | None = None
        self.last_activity = time.monotonic()

    def touch(self) -> None:
        self.last_activity = time.monotonic()

    def guard_auto_lock(self) -> None:
        if time.monotonic() - self.last_activity > AUTO_LOCK_SECONDS:
            raise AutoLockError("Vault auto-locked after inactivity. Please relaunch and unlock again.")

    def ask(self, message: str) -> str:
        self.guard_auto_lock()
        value = prompt(message)
        self.touch()
        return value

    def ask_confirm(self, message: str, default: bool = False) -> bool:
        self.guard_auto_lock()
        value = confirm(message, default=default)
        self.touch()
        return value

    def ask_secret(self, message: str) -> str:
        self.guard_auto_lock()
        value = getpass.getpass(message)
        self.touch()
        return value

    def ask_password_value(self, allow_generate: bool = True, current: str | None = None) -> str:
        while True:
            if allow_generate:
                choice = self.ask("[M]anual password, [G]enerate password, or [K]eep current? ").lower() if current is not None else self.ask("[M]anual password or [G]enerate password? ").lower()
                if current is not None and choice in {"", "k", "keep"}:
                    return current
                if choice in {"g", "generate"}:
                    generated = self.interactive_generate_password()
                    print(f"Generated password: {generated}")
                    label, _ = password_strength(generated)
                    print(f"Strength: {label}")
                    if self.ask_confirm("Use this password?", default=True):
                        return generated
                    continue
                if choice not in {"m", "manual", ""}:
                    print("Please choose manual, generate, or keep.")
                    continue
            entered = self.ask_secret("Password: ")
            if current is not None and not entered:
                return current
            label, _ = password_strength(entered)
            print(f"Strength: {label}")
            confirm_value = self.ask_secret("Confirm password: ")
            if entered != confirm_value:
                print("Passwords do not match.")
                continue
            return entered

    def unlock(self) -> None:
        clear_screen()
        print(f"{APP_NAME} stores everything offline in {self.vault_path}")
        if not self.vault_path.exists():
            print("\nNo vault found. Let's create one.")
            while True:
                master = self.ask_secret("Create a master password: ")
                label, _ = password_strength(master)
                print(f"Master password strength: {label}")
                if len(master) < MIN_MASTER_PASSWORD_LENGTH:
                    print(f"Use at least {MIN_MASTER_PASSWORD_LENGTH} characters.")
                    continue
                confirm_master = self.ask_secret("Confirm master password: ")
                if master != confirm_master:
                    print("Passwords do not match.")
                    continue
                self.store = VaultStore.initialize_new(self.vault_path, master)
                print("Vault created successfully.")
                return

        for attempt in range(3):
            master = self.ask_secret("Enter master password: ")
            try:
                self.store = VaultStore.unlock(self.vault_path, master)
                print("Vault unlocked.")
                return
            except AuthenticationError as exc:
                print(exc)
                if attempt == 2:
                    raise

    def run(self) -> None:
        self.unlock()
        while True:
            print_header(APP_NAME)
            print("1. View entries")
            print("2. Add entry")
            print("3. Search entries")
            print("4. Generate password")
            print("5. Change master password")
            print("6. Export encrypted backup")
            print("7. Import encrypted backup")
            print("8. Exit")
            choice = self.ask("Choose an option: ")
            if choice == "1":
                self.view_entries()
            elif choice == "2":
                self.add_entry()
            elif choice == "3":
                self.search_entries()
            elif choice == "4":
                generated = self.interactive_generate_password()
                print(f"Generated password: {generated}")
                if self.ask_confirm("Copy to clipboard?", default=True):
                    self.copy_password(generated)
            elif choice == "5":
                self.change_master_password()
            elif choice == "6":
                self.export_backup()
            elif choice == "7":
                self.import_backup()
            elif choice == "8":
                self.close()
                print("Vault locked.")
                return
            else:
                print("Unknown option.")

    @property
    def active_store(self) -> VaultStore:
        if not self.store:
            raise VaultError("Vault is not unlocked.")
        return self.store

    def view_entries(self) -> None:
        entries = self.active_store.list_entries()
        if not entries:
            print("No entries saved yet.")
            return

        print_header("Stored entries")
        for index, entry in enumerate(entries, start=1):
            print(f"{index}. {summarize_entry(entry)}")
        raw = self.ask("Select an entry number (or press Enter to return): ")
        if not raw:
            return
        try:
            chosen = entries[int(raw) - 1]
        except (ValueError, IndexError):
            print("Invalid selection.")
            return
        self.entry_details_menu(chosen["id"])

    def entry_details_menu(self, entry_id: str) -> None:
        entry = self.active_store.find_by_id(entry_id)
        if not entry:
            print("Entry not found.")
            return

        while True:
            entry = self.active_store.find_by_id(entry_id)
            if not entry:
                print("Entry no longer exists.")
                return
            print_header(entry["title"])
            print(f"Username : {entry['username']}")
            print(f"Password : {mask_secret(entry['secret'])}")
            print(f"URL      : {entry.get('url') or '-'}")
            print(f"Notes    : {entry.get('notes') or '-'}")
            print(f"Updated  : {entry.get('updated_at', '-')}")
            print("1. Show password")
            print("2. Copy password")
            print("3. Edit entry")
            print("4. Delete entry")
            print("5. Back")
            choice = self.ask("Choose an option: ")
            if choice == "1":
                print(f"Password: {entry['secret']}")
            elif choice == "2":
                self.copy_secret(entry["secret"])
            elif choice == "3":
                self.edit_entry(entry)
                return
            elif choice == "4":
                if self.ask_confirm(f"Delete '{entry['title']}'?", default=False):
                    self.active_store.delete_entry(entry_id)
                    print("Entry deleted.")
                    return
            elif choice == "5":
                return
            else:
                print("Unknown option.")

    def add_entry(self) -> None:
        print_header("Add entry")
        title = self.ask("Service/title: ")
        username = self.ask("Username: ")
        if not title or not username:
            print("Title and username are required.")
            return
        secret_value = self.ask_password_value(allow_generate=True)
        url = self.ask("URL (optional): ")
        notes = self.ask("Notes (optional): ")
        entry = {
            "id": uuid.uuid4().hex,
            "title": title,
            "username": username,
            "secret": secret_value,
            "url": url,
            "notes": notes,
            "created_at": now_iso(),
            "updated_at": now_iso(),
        }
        self.active_store.add_entry(entry)
        print("Entry added.")

    def edit_entry(self, entry: dict[str, Any]) -> None:
        print_header(f"Edit {entry['title']}")
        title = self.ask(f"Service/title [{entry['title']}]: ") or entry["title"]
        username = self.ask(f"Username [{entry['username']}]: ") or entry["username"]
        change_password = self.ask_confirm("Update the password?", default=False)
        secret_value = entry["secret"]
        if change_password:
            secret_value = self.ask_password_value(allow_generate=True, current=entry["secret"])
        url = self.ask(f"URL [{entry.get('url') or ''}]: ") or entry.get("url", "")
        notes = self.ask(f"Notes [{entry.get('notes') or ''}]: ") or entry.get("notes", "")
        updated = {
            "title": title,
            "username": username,
            "secret": secret_value,
            "url": url,
            "notes": notes,
        }
        self.active_store.update_entry(entry["id"], updated)
        print("Entry updated.")

    def search_entries(self) -> None:
        term = self.ask("Search term: ")
        if not term:
            return
        results = self.active_store.search(term)
        if not results:
            print("No matches found.")
            return
        print_header(f"Results for '{term}'")
        for index, entry in enumerate(results, start=1):
            print(f"{index}. {summarize_entry(entry)}")
        raw = self.ask("Select an entry number (or press Enter to return): ")
        if not raw:
            return
        try:
            chosen = results[int(raw) - 1]
        except (ValueError, IndexError):
            print("Invalid selection.")
            return
        self.entry_details_menu(chosen["id"])

    def interactive_generate_password(self) -> str:
        print_header("Generate password")
        length = prompt_int("Length", 20, 8, 128)
        use_upper = confirm("Include uppercase letters?", True)
        use_lower = confirm("Include lowercase letters?", True)
        use_digits = confirm("Include numbers?", True)
        use_symbols = confirm("Include symbols?", True)
        exclude_ambiguous = confirm("Exclude ambiguous characters (0/O/1/l/I)?", False)
        password_value = generate_password(
            length=length,
            use_upper=use_upper,
            use_lower=use_lower,
            use_digits=use_digits,
            use_symbols=use_symbols,
            exclude_ambiguous=exclude_ambiguous,
        )
        label, _ = password_strength(password_value)
        print(f"Strength: {label}")
        return password_value

    def copy_secret(self, secret_value: str) -> None:
        timeout = prompt_int("Clipboard clear timeout in seconds", self.clipboard_timeout, 5, 600)
        try:
            self.clipboard.copy_with_timeout(secret_value, timeout_seconds=timeout)
            print(f"Copied to clipboard. It will be cleared in {timeout} seconds.")
        except ClipboardError as exc:
            print(exc)

    def change_master_password(self) -> None:
        print_header("Change master password")
        current_secret = self.ask_secret("Re-enter current master password: ")
        try:
            VaultStore.unlock(self.vault_path, current_secret)
        except AuthenticationError:
            print("Current master password did not match.")
            return
        while True:
            new_master_secret = self.ask_secret("New master password: ")
            label, _ = password_strength(new_master_secret)
            print(f"New master password strength: {label}")
            if len(new_master_secret) < MIN_MASTER_PASSWORD_LENGTH:
                print(f"Use at least {MIN_MASTER_PASSWORD_LENGTH} characters.")
                continue
            confirm_master_secret = self.ask_secret("Confirm new master password: ")
            if new_master_secret != confirm_master_secret:
                print("Passwords do not match.")
                continue
            self.active_store.change_master_password(new_master_secret)
            print("Master password changed.")
            return

    def export_backup(self) -> None:
        print_header("Export encrypted backup")
        destination = self.ask(f"Backup path [{self.vault_path.with_suffix(self.vault_path.suffix + BACKUP_SUFFIX)}]: ")
        target = Path(destination) if destination else self.vault_path.with_suffix(self.vault_path.suffix + BACKUP_SUFFIX)
        self.active_store.export_backup(target)
        print(f"Encrypted backup written to {target}")

    def import_backup(self) -> None:
        print_header("Import encrypted backup")
        source = self.ask("Backup file path: ")
        if not source:
            return
        source_path = Path(source).expanduser()
        if not source_path.exists():
            print("Backup file not found.")
            return
        if not self.ask_confirm("Importing replaces the current vault contents. Continue?", default=False):
            return
        backup_secret = self.ask_secret("Backup master password: ")
        self.active_store.import_backup(source_path, backup_secret)
        print("Backup imported and re-encrypted with the current master password.")

    def close(self) -> None:
        if self.store:
            best_effort_wipe(self.store.key_material)
            self.store.data.clear()
            self.store = None


def run_cli(vault_path: Path, clipboard_timeout: int) -> int:
    app = CobraVaultCLI(vault_path=vault_path, clipboard_timeout=clipboard_timeout)
    try:
        app.run()
        return 0
    except (DependencyError, VaultError, AutoLockError) as exc:
        print(f"\nError: {exc}")
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted. Vault locked.")
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Offline password manager")
    parser.add_argument(
        "--vault",
        type=Path,
        default=Path(__file__).resolve().with_name(VAULT_FILENAME),
        help="Path to the encrypted vault file (defaults next to the script).",
    )
    parser.add_argument(
        "--clipboard-timeout",
        type=int,
        default=DEFAULT_CLIPBOARD_TIMEOUT,
        help="Default clipboard clear timeout in seconds.",
    )
    parser.add_argument(
        "--generate-password",
        action="store_true",
        help="Generate one password and exit.",
    )
    parser.add_argument(
        "--length",
        type=int,
        default=20,
        help="Password length for --generate-password.",
    )
    parser.add_argument(
        "--no-symbols",
        action="store_true",
        help="Exclude symbols when using --generate-password.",
    )
    parser.add_argument(
        "--clear-clipboard",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--timeout", type=int, default=DEFAULT_CLIPBOARD_TIMEOUT, help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.clear_clipboard:
        ClipboardManager(script_path=Path(__file__).resolve()).clear_after_timeout(timeout_seconds=args.timeout)
        return 0

    if args.generate_password:
        print(
            generate_password(
                length=args.length,
                use_symbols=not args.no_symbols,
            )
        )
        return 0

    ensure_dependencies()
    return run_cli(vault_path=args.vault.expanduser().resolve(), clipboard_timeout=args.clipboard_timeout)


if __name__ == "__main__":
    raise SystemExit(main())
