"""Windows system proxy (the same switch v2rayN uses). No-ops on other systems so tests can run anywhere."""
import ctypes
import sys

IS_WINDOWS = sys.platform == "win32"
_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
BYPASS = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.2*;172.30.*;172.31.*;192.168.*;<local>"


def is_admin():
    if not IS_WINDOWS:
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _notify():
    try:
        w = ctypes.windll.wininet
        w.InternetSetOptionW(None, 39, None, 0)  # settings changed
        w.InternetSetOptionW(None, 37, None, 0)  # refresh
    except Exception:
        pass


def get_state():
    """Current proxy settings, so they can be restored exactly."""
    if not IS_WINDOWS:
        return {}
    import winreg
    state = {}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _KEY, 0, winreg.KEY_READ) as k:
        for name in ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL"):
            try:
                state[name] = winreg.QueryValueEx(k, name)
            except FileNotFoundError:
                state[name] = None
    return state


def enable(host_port):
    if not IS_WINDOWS:
        return
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _KEY, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, host_port)
        winreg.SetValueEx(k, "ProxyOverride", 0, winreg.REG_SZ, BYPASS)
        try:
            winreg.DeleteValue(k, "AutoConfigURL")  # a PAC script would override our proxy
        except FileNotFoundError:
            pass
    _notify()


def restore(state):
    if not IS_WINDOWS:
        return
    import winreg
    state = state or {}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _KEY, 0, winreg.KEY_SET_VALUE) as k:
        for name in ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL"):
            item = state.get(name)
            if item is None:
                if name == "ProxyEnable":
                    winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, 0)
                else:
                    try:
                        winreg.DeleteValue(k, name)
                    except FileNotFoundError:
                        pass
            else:
                winreg.SetValueEx(k, name, 0, item[1], item[0])
    _notify()
