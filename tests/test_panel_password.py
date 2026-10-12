"""Password reset through a real Linux PTY; all host paths/tools are sandboxed."""
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import tempfile
import time
import unittest

if os.name == "posix":
    import fcntl
    import pty
    import termios


class Terminal:
    def __init__(self, command, env, *, stdin_redirected=False, raw_cr=False):
        self.master, self.slave = pty.openpty()
        if raw_cr:
            attrs = termios.tcgetattr(self.slave)
            attrs[0] &= ~termios.ICRNL
            termios.tcsetattr(self.slave, termios.TCSANOW, attrs)

        def child_terminal():
            os.setsid()
            fcntl.ioctl(self.slave, termios.TIOCSCTTY, 0)

        self.proc = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL if stdin_redirected else self.slave,
                                     stdout=self.slave, stderr=self.slave, preexec_fn=child_terminal,
                                     pass_fds=(self.slave,))
        self.output = bytearray()
        self.pending = bytearray()

    def read(self, timeout=.1):
        if select.select([self.master], [], [], timeout)[0]:
            try:
                data = os.read(self.master, 65536)
            except OSError:
                data = b""
            self.output.extend(data)
            self.pending.extend(data)

    def wait_for(self, text):
        marker = text.encode()
        deadline = time.monotonic() + 8
        while marker not in self.pending:
            self.read()
            if time.monotonic() > deadline or self.proc.poll() is not None:
                raise AssertionError(f"Missing prompt {text!r}: {self.output.decode(errors='replace')}")
        end = self.pending.index(marker) + len(marker)
        del self.pending[:end]

    def send(self, value):
        os.write(self.master, value.encode() if isinstance(value, str) else value)

    def finish(self):
        deadline = time.monotonic() + 10
        while self.proc.poll() is None:
            self.read()
            if time.monotonic() > deadline:
                raise AssertionError("Installer did not finish")
        self.read()
        return self.proc.returncode

    def close(self):
        if self.proc.poll() is None:
            os.killpg(self.proc.pid, signal.SIGKILL)
        self.proc.wait(timeout=5)
        os.close(self.master)
        os.close(self.slave)


@unittest.skipUnless(os.name == "posix", "Linux controlling-terminal semantics required")
class PanelPasswordTests(unittest.TestCase):
    password = "FixtureOnly!literal*Z9"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="runman-password-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.agent = self.root / "agent"
        self.agent.mkdir()
        self.mock = self.root / "bin"
        self.mock.mkdir()
        self.calls = self.root / "calls"
        self.config = self.agent / "config.json"
        self.original = json.dumps({"web_pass_hash": "fixture-existing-hash", "token": "fixture-token", "virt_type": "incus"})
        self.config.write_text(self.original, encoding="utf-8")
        source = (Path(__file__).resolve().parents[1] / "install.sh").read_text(encoding="utf-8")
        source = source.replace("/opt/narwhal-agent", str(self.agent)).replace("/var/lib/narwhal-agent", str(self.root / "data"))
        self.script = self.root / "install.sh"
        self.script.write_text(source, encoding="utf-8", newline="\n")
        self.tool(self.agent / "narwhal-agent", '''
test "$1" = --config && test "$2" = "$TEST_CONFIG" && test "$3" = --reset-password
test "$4" = "$TEST_PASSWORD"
echo reset >> "$TEST_CALLS"
test "${TEST_RESET_FAIL:-0}" != 1
''')
        self.tool(self.mock / "systemctl", '''
test "$*" = 'restart narwhal-agent'
echo restart >> "$TEST_CALLS"
test "${TEST_RESTART_FAIL:-0}" != 1
''')
        self.env = dict(os.environ, PATH=str(self.mock) + ":" + os.environ["PATH"], LC_ALL="C.UTF-8",
                        TEST_CONFIG=str(self.config), TEST_PASSWORD=self.password, TEST_CALLS=str(self.calls), TEST_SCRIPT=str(self.script))
        for key in list(self.env):
            if key.startswith(("INCUS_", "IPV6_", "PODMAN_", "RUNMAN_", "NARWHAL_")) or key == "TMOUT":
                del self.env[key]

    @staticmethod
    def tool(path, body):
        path.write_text("#!/bin/bash\nset -e\n" + body, encoding="utf-8", newline="\n")
        path.chmod(0o755)

    def start(self, *, mode="file", stdin_redirected=False, raw_cr=False):
        if mode == "menu":
            command = ["bash", "-c", 'bash <(cat "$TEST_SCRIPT")']
        elif mode == "pipe":
            command = ["bash", "-c", 'cat "$TEST_SCRIPT" | bash -s -- en --reset-panel-password']
        else:
            command = ["bash", str(self.script), "en", "--reset-panel-password"]
        terminal = Terminal(command, self.env, stdin_redirected=stdin_redirected, raw_cr=raw_cr)
        self.addCleanup(terminal.close)
        return terminal

    def assert_success(self, terminal):
        self.assertEqual(terminal.finish(), 0, terminal.output.decode(errors="replace"))
        self.assertEqual(self.calls.read_text().splitlines(), ["reset", "restart"])
        self.assertNotIn(self.env["TEST_PASSWORD"].encode(), terminal.output)
        self.assertTrue(termios.tcgetattr(terminal.slave)[3] & termios.ECHO, "terminal echo not restored")

    def enter_password(self, terminal):
        terminal.wait_for("New panel password")
        terminal.send(self.env["TEST_PASSWORD"] + "\n")
        terminal.wait_for("Confirm new panel password")
        terminal.send(self.env["TEST_PASSWORD"] + "\n")

    def test_special_characters_and_whitespace_preserved_without_echo(self):
        self.env["TEST_PASSWORD"] = "  Fixture!literal\\*$()'\"  "
        terminal = self.start()
        self.enter_password(terminal)
        self.assert_success(terminal)

    def test_streamed_installer_chinese_menu_and_crlf_paste(self):
        terminal = self.start(mode="menu")
        terminal.wait_for("> ")
        terminal.send("2\n")
        terminal.wait_for("> ")
        terminal.send("4\n")
        terminal.wait_for("新面板密码")
        terminal.send(self.password + "\r\n")
        terminal.wait_for("再次输入新面板密码")
        terminal.send(self.password + "\r\n")
        self.assert_success(terminal)

    def test_piped_script_reads_secrets_from_controlling_terminal(self):
        terminal = self.start(mode="pipe")
        self.enter_password(terminal)
        self.assert_success(terminal)

    def test_redirected_stdin_still_reads_terminal(self):
        terminal = self.start(stdin_redirected=True)
        self.enter_password(terminal)
        self.assert_success(terminal)

    def test_literal_crlf_from_terminal_is_normalized(self):
        terminal = self.start(raw_cr=True)
        terminal.wait_for("New panel password")
        terminal.send(self.password + "\r\n")
        terminal.wait_for("Confirm new panel password")
        terminal.send(self.password + "\r\n")
        self.assert_success(terminal)

    def test_empty_confirmation_reprompts_instead_of_exiting(self):
        terminal = self.start()
        terminal.wait_for("New panel password")
        terminal.send(self.password + "\n")
        terminal.wait_for("Confirm new panel password")
        terminal.send("\n")
        terminal.wait_for("Confirmation is empty")
        terminal.wait_for("Confirm new panel password")
        self.assertIsNone(terminal.proc.poll())
        self.assertFalse(self.calls.exists())
        terminal.send(self.password + "\n")
        self.assert_success(terminal)

    def test_mismatch_retries_without_leaking_secret_to_shell(self):
        terminal = self.start()
        terminal.wait_for("New panel password")
        terminal.send(self.password + "\n")
        terminal.wait_for("Confirm new panel password")
        terminal.send("FixtureOnlyWrong!Z9\n")
        terminal.wait_for("Passwords do not match")
        self.assertFalse(self.calls.exists())
        self.enter_password(terminal)
        self.assert_success(terminal)
        self.assertNotIn(b"FixtureOnlyWrong!Z9", terminal.output)

    def test_blank_short_and_overlong_passwords_retry_before_confirmation(self):
        terminal = self.start()
        for password in ("", "short", "a" * 73, "密" * 25):
            terminal.wait_for("New panel password")
            terminal.send(password + "\n")
            terminal.wait_for("Please try again")
            self.assertFalse(self.calls.exists())
        self.enter_password(terminal)
        self.assert_success(terminal)

    def test_eof_cancels_without_modification_or_restart(self):
        terminal = self.start()
        terminal.wait_for("New panel password")
        terminal.send(b"\x04")
        self.assertNotEqual(terminal.finish(), 0)
        self.assertIn(b"Password reset cancelled", terminal.output)
        self.assertFalse(self.calls.exists())
        self.assertEqual(self.config.read_text(), self.original)
        self.assertTrue(termios.tcgetattr(terminal.slave)[3] & termios.ECHO)

    def test_ctrl_c_cancels_and_restores_echo(self):
        terminal = self.start()
        terminal.wait_for("New panel password")
        terminal.send(b"\x03")
        self.assertNotEqual(terminal.finish(), 0)
        self.assertFalse(self.calls.exists())
        self.assertEqual(self.config.read_text(), self.original)
        self.assertTrue(termios.tcgetattr(terminal.slave)[3] & termios.ECHO)

    def test_save_failure_does_not_restart_agent(self):
        self.env["TEST_RESET_FAIL"] = "1"
        terminal = self.start()
        self.enter_password(terminal)
        self.assertNotEqual(terminal.finish(), 0)
        self.assertEqual(self.calls.read_text().splitlines(), ["reset"])
        self.assertIn(b"Failed to save", terminal.output)
        self.assertNotIn(self.password.encode(), terminal.output)

    def test_restart_failure_is_not_reported_as_success(self):
        self.env["TEST_RESTART_FAIL"] = "1"
        terminal = self.start()
        self.enter_password(terminal)
        self.assertNotEqual(terminal.finish(), 0)
        self.assertIn(b"Password saved, but Agent restart failed", terminal.output)
        self.assertNotIn(b"Panel password reset; Agent restarted", terminal.output)

    def test_no_terminal_and_noninteractive_mode_fail_closed(self):
        for extra in ([], ["--non-interactive"]):
            result = subprocess.run(["bash", str(self.script), "en", "--reset-panel-password", *extra],
                                    env=self.env, stdin=subprocess.DEVNULL, capture_output=True, start_new_session=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"requires an interactive terminal", result.stderr)
            self.assertFalse(self.calls.exists())
            self.assertEqual(self.config.read_text(), self.original)


if __name__ == "__main__":
    unittest.main()
