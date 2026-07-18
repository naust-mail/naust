"""
Component registry. Each defs/*.py file exposes a COMPONENT instance and a
make_tasks(env, runtime) function. The runner imports all defs and uses these.
"""

from dataclasses import dataclass, field
from collections.abc import Callable

BAREMETAL = "baremetal"
DOCKER = "docker"


@dataclass
class Component:
	"""Declares what a component needs (packages, services) and when it applies.

	The actual build/configure logic lives in the accompanying make_tasks()
	function in the same defs file - not here.
	"""

	# Unique identifier, used as the doit task group name.
	name: str
	# apt packages to install before any tasks run (batched across all components).
	packages: list[str] = field(default_factory=list)
	# systemd units restarted after tasks run on bare metal.
	services: list[str] = field(default_factory=list)
	# supervisorctl targets restarted after tasks run in Docker.
	docker_services: list[str] = field(default_factory=list)
	# If set, component is skipped when enabled(env) returns False.
	enabled: Callable | None = None
	# Skip this entire component in the listed runtimes.
	skip_on: list[str] = field(default_factory=list)
	# Run order relative to other components. Lower numbers run first.
	# Components with equal port_order run in alphabetical filename order.
	port_order: int = 100
	# Informational notices printed at the end of setup. Use for licensing
	# obligations or operator-facing information that must not get lost in
	# the install output stream.
	notices: list[str] = field(default_factory=list)
	# Unix groups this component creates (via its own tasks, not a package)
	# that the naust user needs read access to for backups. Collated across
	# all enabled components and granted once after every component's tasks
	# have finished, so ordering against the group's own creation is never
	# an issue. Skipped individually if the group doesn't exist.
	naust_backup_groups: list[str] = field(default_factory=list)
