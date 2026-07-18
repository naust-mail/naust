from dataclasses import dataclass, field
from collections.abc import Callable


# A single step inside a check's run. Mirrors how a CI job shows its steps:
# each one has a name, a status, and (if it failed) a message saying why.
@dataclass
class StepResult:
	name: str
	status: str = "running"  # running | ok | warning | error
	message: str = ""
	started_at: float = 0.0
	finished_at: float | None = None


# The result of one whole check (one or more steps).
@dataclass
class CheckResult:
	name: str
	category: str
	status: str  # ok | warning | error | skipped
	message: str = ""
	steps: list = field(default_factory=list)  # list[StepResult]
	domain: str | None = None  # set when this result is one instance of a per-domain check


@dataclass
class Check:
	name: str
	category: str
	fn: Callable
	depends_on: list = field(default_factory=list)
	# enabled(env) -> bool. None means always enabled.
	enabled: Callable | None = None
	# per_domain(env) -> iterable of domain strings. None means this check runs once.
	per_domain: Callable | None = None


# All checks that have registered themselves by being imported.
REGISTRY: dict = {}


def check(name, category, depends_on=(), enabled=None, per_domain=None):
	"""Decorator that registers a function as a status check.

	A file becomes a check just by being imported - dropping a new file in
	checks/ and decorating one function in it is the entire registration
	step. Deleting the file removes the check.
	"""

	def decorator(fn):
		REGISTRY[name] = Check(
			name=name,
			category=category,
			fn=fn,
			depends_on=list(depends_on),
			enabled=enabled,
			per_domain=per_domain,
		)
		return fn

	return decorator
