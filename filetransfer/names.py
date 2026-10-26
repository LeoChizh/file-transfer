"""Turn whatever a browser sends into a safe name inside the upload folder."""
import os


def clean_name(raw):
    # browsers (and old IE) may send either separator, whatever the server OS
    name = raw.replace("\\", "/").split("/")[-1]
    name = "".join(c for c in name if c >= " " and c not in '<>:"|?*')
    name = name.strip(" .")
    return name or "upload"


def unique_path(upload_dir, name):
    """Atomically reserve upload_dir/name, adding ' (n)' if it is taken."""
    stem, ext = os.path.splitext(name)
    candidate, n = name, 0
    while True:
        path = os.path.join(upload_dir, candidate)
        try:
            os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
            return candidate, path
        except FileExistsError:
            n += 1
            candidate = f"{stem} ({n}){ext}"
