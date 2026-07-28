"""
Component registry. Each defs/*.py file exposes a COMPONENT instance and a
make_tasks(env, runtime) function. The runner imports all defs and uses these.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
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
	# Callable(env, runtime) run once, after every enabled component's doit
	# tasks have finished (before service restarts). For fixups that depend
	# on another component's output existing but can't be expressed as a
	# doit task_dep without hurting parallelism - e.g. re-owning a secret
	# that had to be created by an earlier-running component before this
	# component's own runtime user existed. Runs unconditionally on every
	# invocation regardless of what doit considers cached, so keep it fast
	# and idempotent. Hooks across different components are NOT ordered
	# relative to each other - only guaranteed to run after every doit task
	# has finished. A hook may depend on other components' doit output, but
	# never on another component's post_install having already run.
	post_install: Callable[[dict, str], None] | None = None
