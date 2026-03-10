# runner.py
import subprocess
import threading
import os
import signal
import time

print_lock = threading.Lock()

def execute(cmd_list, timeout=300, cwd=None, env=None):
    """
    Runs command with HARD timeout (kills whole process group),
    but returns stdout as string (or None) to stay compatible with your modules.
    """
    try:
        proc = subprocess.Popen(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=cwd,
            env=env,
            start_new_session=True  # new process group
        )

        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            # kill whole process group
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except Exception:
                pass

            time.sleep(1.0)

            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except Exception:
                    pass

            with print_lock:
                print(f"[!] Timeout: {cmd_list[0]} exceeded {timeout} seconds. Killing process group...")

            try:
                stdout, stderr = proc.communicate(timeout=3)
            except Exception:
                stdout, stderr = "", ""

            stdout = (stdout or "").strip()
            return stdout if stdout else None

        stdout = (stdout or "").strip()
        stderr = (stderr or "").strip()

        if proc.returncode != 0:
            with print_lock:
                print(f"[!] {cmd_list[0]} exited with code {proc.returncode}")
                if stderr:
                    print(stderr)
            return stdout if stdout else None

        return stdout if stdout else None

    except FileNotFoundError:
        with print_lock:
            print(f"[!] Tool not found: {cmd_list[0]}. Is it installed?")
        return None

    except Exception as e:
        with print_lock:
            print(f"[!] Unexpected execution error in {cmd_list[0]}: {str(e)}")
        return None
