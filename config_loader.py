import os
import yaml

DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yaml")


def load_config(config_path=None):
    path = config_path or DEFAULT_CONFIG_PATH
    if os.path.exists(path):
        with open(path, "r") as f:
            return yaml.safe_load(f)
    return get_defaults()


def get_defaults():
    return {
        "rules": {
            "si_fn_mismatch": {"enabled": True, "score": 40},
            "zeroed_nanoseconds": {"enabled": True, "score": 30, "user_paths_only": True},
            "birthtime_mtime_gap": {"enabled": True, "score": 35, "min_gap_seconds": 3600},
            "log_clearing": {"enabled": True, "score": 50},
            "clock_jump": {"enabled": True, "score": 45, "min_jump_minutes": 5},
            "record_sequence_gap": {"enabled": True, "score": 45, "min_gap": 5},
            "system_time_change": {"enabled": True, "score": 40},
            "touch_command": {"enabled": True, "score": 35},
            "utimes_syscall": {"enabled": True, "score": 40},
            "linux_clock_change": {"enabled": True, "score": 45},
        },
        "scan": {
            "exclude_paths": [
                "Windows", "Program Files", "Program Files (x86)",
                "AppData", "ProgramData", "System32", "SysWOW64",
            ],
            "target_paths": [],
        },
        "severity": {"high": 70, "medium": 40},
        "custom_rules": [],
    }
