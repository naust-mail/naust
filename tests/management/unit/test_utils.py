from core.utils import safe_domain_name, sort_domains, load_env_vars_from_file


# ---------------------------------------------------------------------------
# safe_domain_name
# ---------------------------------------------------------------------------


class TestSafeDomainName:
	def test_plain_domain_unchanged(self):
		assert safe_domain_name("example.com") == "example.com"

	def test_slash_is_encoded(self):
		result = safe_domain_name("example.com/path")
		assert "/" not in result
		assert "%2F" in result

	def test_colon_is_encoded(self):
		result = safe_domain_name("example.com:8080")
		assert ":" not in result

	def test_subdomain_unchanged(self):
		assert safe_domain_name("mail.example.com") == "mail.example.com"

	def test_unicode_domain_encoded(self):
		result = safe_domain_name("例え.jp")
		assert "例え" not in result


# ---------------------------------------------------------------------------
# sort_domains
# ---------------------------------------------------------------------------


class TestSortDomains:
	def _env(self, primary):
		return {"PRIMARY_HOSTNAME": primary}

	def test_primary_hostname_is_first(self):
		domains = ["zebra.com", "box.example.com", "alpha.com"]
		env = self._env("box.example.com")
		result = sort_domains(domains, env)
		assert result[0] == "box.example.com"

	def test_subdomains_grouped_under_parent(self):
		domains = ["example.com", "mail.example.com", "other.com"]
		env = self._env("example.com")
		result = sort_domains(domains, env)
		# example.com zone should appear together before other.com
		example_indices = [result.index("example.com"), result.index("mail.example.com")]
		other_index = result.index("other.com")
		assert max(example_indices) < other_index

	def test_alphabetical_within_zone(self):
		domains = ["z.example.com", "a.example.com", "example.com"]
		env = self._env("example.com")
		result = sort_domains(domains, env)
		# example.com itself is first, then subdomains sorted
		assert result[0] == "example.com"
		sub_part = result[1:]
		assert sub_part == sorted(sub_part)

	def test_single_domain(self):
		domains = ["example.com"]
		env = self._env("example.com")
		assert sort_domains(domains, env) == ["example.com"]

	def test_independent_zones_sorted_alpha(self):
		domains = ["zebra.org", "alpha.org"]
		env = self._env("nothere.example.com")
		result = sort_domains(domains, env)
		assert result == ["alpha.org", "zebra.org"]


# ---------------------------------------------------------------------------
# load_env_vars_from_file
# ---------------------------------------------------------------------------


class TestLoadEnvVarsFromFile:
	def test_parses_plain_key_value(self, tmp_path):
		f = tmp_path / "env.conf"
		f.write_text("KEY=value\n")
		env = load_env_vars_from_file(str(f))
		assert env["KEY"] == "value"

	def test_parses_single_quoted_value(self, tmp_path):
		f = tmp_path / "env.conf"
		f.write_text("KEY='hello world'\n")
		env = load_env_vars_from_file(str(f))
		assert env["KEY"] == "hello world"

	def test_parses_double_quoted_value(self, tmp_path):
		f = tmp_path / "env.conf"
		f.write_text('KEY="hello world"\n')
		env = load_env_vars_from_file(str(f))
		assert env["KEY"] == "hello world"

	def test_ignores_hash_comments(self, tmp_path):
		f = tmp_path / "env.conf"
		f.write_text("# this is a comment\nKEY=value\n")
		env = load_env_vars_from_file(str(f))
		assert "# this is a comment" not in env
		assert env["KEY"] == "value"

	def test_ignores_blank_lines(self, tmp_path):
		f = tmp_path / "env.conf"
		f.write_text("\nKEY=value\n\n")
		env = load_env_vars_from_file(str(f))
		assert env["KEY"] == "value"
		assert len(env) == 1

	def test_skips_lines_without_equals(self, tmp_path):
		f = tmp_path / "env.conf"
		f.write_text("MALFORMED\nKEY=value\n")
		env = load_env_vars_from_file(str(f))
		assert "MALFORMED" not in env
		assert env["KEY"] == "value"

	def test_multiple_keys(self, tmp_path):
		f = tmp_path / "env.conf"
		f.write_text("A=1\nB=2\nC=3\n")
		env = load_env_vars_from_file(str(f))
		assert env["A"] == "1"
		assert env["B"] == "2"
		assert env["C"] == "3"

	def test_first_value_wins_on_duplicate(self, tmp_path):
		f = tmp_path / "env.conf"
		f.write_text("KEY=first\nKEY=second\n")
		env = load_env_vars_from_file(str(f))
		assert env["KEY"] == "first"

	def test_empty_value(self, tmp_path):
		f = tmp_path / "env.conf"
		f.write_text("KEY=\n")
		env = load_env_vars_from_file(str(f))
		assert env["KEY"] == ""
