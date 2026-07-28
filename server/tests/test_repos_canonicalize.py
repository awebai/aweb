"""Unit tests for git origin URL canonicalization."""

import pytest

from aweb.coordination.routes.repos import canonicalize_git_url


def test_canonicalize_ssh_shorthand():
    assert canonicalize_git_url("git@github.com:org/repo.git") == "github.com/org/repo"


def test_canonicalize_https():
    assert canonicalize_git_url("https://github.com/org/repo.git") == "github.com/org/repo"


def test_canonicalize_ssh_scheme_with_port():
    assert canonicalize_git_url("ssh://git@github.com:22/org/repo.git") == "github.com/org/repo"


@pytest.mark.parametrize(
    "origin",
    [
        "ssh://git@ssh.github.com:443/org/repo.git",
        "ssh://git@ssh.github.com:443/org/repo",
    ],
)
def test_canonicalize_github_ssh_over_443_hostname(origin):
    assert canonicalize_git_url(origin) == "github.com/org/repo"


def test_canonicalize_ssh_config_alias():
    """SSH-config host aliases (Host github-co-aweb blocks routing to deploy
    keys) are legitimate scp-like git remotes and must canonicalize, not 422."""
    assert (
        canonicalize_git_url("github-co-aweb:awebai/co.aweb.git")
        == "github-co-aweb/awebai/co.aweb"
    )


def test_canonicalize_scp_like_with_user():
    assert canonicalize_git_url("deploy@build-host:team/repo.git") == "build-host/team/repo"


def test_canonicalize_alias_without_path_rejected():
    with pytest.raises(ValueError):
        canonicalize_git_url("github-co-aweb:")


def test_canonicalize_empty_rejected():
    with pytest.raises(ValueError):
        canonicalize_git_url("")


def test_canonicalize_absolute_path_rejected():
    with pytest.raises(ValueError):
        canonicalize_git_url("/srv/git/repo.git")
