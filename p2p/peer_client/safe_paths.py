import os


def resolve_inside(base_dir, name):
    """Return the real path of file `name` inside `base_dir`, or None if unsafe.

    `name` comes from the network (another peer or the tracker), so only a bare
    file name is accepted: no directory parts, no absolute path, no "." or "..".
    The resolved path must also stay inside `base_dir` after following symlinks.
    """
    if not isinstance(name, str) or name in ("", ".", "..") or "\x00" in name:
        return None
    if "/" in name or "\\" in name or os.path.basename(name) != name:
        return None
    base = os.path.realpath(base_dir)
    path = os.path.realpath(os.path.join(base, name))
    if os.path.commonpath([base, path]) != base:
        return None
    return path
