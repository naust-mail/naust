"""
Install apt packages for the named components.

Used in Dockerfiles at build time so packages are baked into the image:

    RUN python3 -m components.install_packages dns ssl

Only reads COMPONENT.packages - does not call make_tasks() and does not
require /etc/naust.conf. At build time RUNTIME is unset so
packages.ensure_installed() runs apt normally. At container runtime
RUNTIME=docker so ensure_installed() is a no-op (packages already present).
"""

import importlib
import pkgutil
import sys


def main(component_names: list[str]) -> None:
	import components.defs as defs_pkg
	from components.packages import ensure_installed

	known: dict[str, list[str]] = {}
	for _, modname, ispkg in pkgutil.walk_packages(defs_pkg.__path__, defs_pkg.__name__ + "."):
		if ispkg:
			continue
		mod = importlib.import_module(modname)
		if hasattr(mod, "COMPONENT"):
			c = mod.COMPONENT
			known[c.name] = c.packages

	missing = [n for n in component_names if n not in known]
	if missing:
		print(f"ERROR: unknown components: {missing}", file=sys.stderr)
		print(f"Known: {sorted(known)}", file=sys.stderr)
		sys.exit(1)

	packages = sorted({p for name in component_names for p in known[name]})
	if packages:
		print(f"Installing packages for {component_names}: {packages}")
		ensure_installed(packages)
	else:
		print(f"No packages to install for {component_names}")


if __name__ == "__main__":
	main(sys.argv[1:])
