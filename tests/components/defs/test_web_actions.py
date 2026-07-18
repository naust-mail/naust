"""Regression tests for web component action functions.

The fresh-box dual-nginx-config outage (2026-07-10): a leftover
/etc/nginx/conf.d/local.conf from the legacy stack silently shadows
every naust.d site because nginx treats duplicate server names as a
warning and conf.d sorts local.conf first. _managed_sites must remove
it on bare metal; the only source of one today is an upstream
Mail-in-a-Box being migrated. In Docker, management never writes
local.conf at all (Flask is retired there), so _managed_sites must
leave it alone - deleting it there would just race whatever wrote it,
for no benefit.
"""

from unittest import mock

from setup.components.defs import web
from setup.components.component import BAREMETAL, DOCKER


def test_managed_sites_removes_legacy_local_conf_on_baremetal():
	removed = []
	with mock.patch.object(web.os, "makedirs"), mock.patch.object(web.os, "chmod"), mock.patch.object(web.artifacts, "write_file"), mock.patch.object(web.os, "remove", side_effect=removed.append):
		web._managed_sites(BAREMETAL)  # noqa: SLF001
	assert removed == ["/etc/nginx/conf.d/local.conf"]


def test_managed_sites_tolerates_absent_local_conf_on_baremetal():
	def raise_missing(path):
		raise FileNotFoundError(path)

	with mock.patch.object(web.os, "makedirs"), mock.patch.object(web.os, "chmod"), mock.patch.object(web.artifacts, "write_file"), mock.patch.object(web.os, "remove", side_effect=raise_missing):
		web._managed_sites(BAREMETAL)  # must not raise  # noqa: SLF001


def test_managed_sites_leaves_local_conf_alone_in_docker():
	with mock.patch.object(web.os, "makedirs"), mock.patch.object(web.os, "chmod"), mock.patch.object(web.artifacts, "write_file"), mock.patch.object(web.os, "remove") as remove:
		web._managed_sites(DOCKER)  # noqa: SLF001
	remove.assert_not_called()
