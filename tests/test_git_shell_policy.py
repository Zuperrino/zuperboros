"""Regression suite for the external-workspace git policy classifier.

These pin the bypasses found in the v6.27.0 audit (NW-4): environment-based
repo retargeting (``GIT_DIR`` / ``GIT_WORK_TREE``) and glued / newline shell
separators that previously let ``cd ws;git -C <runtime> reset`` masquerade as a
single ``cd`` segment with the ``-C`` selector never inspected. The round-1
``cd``-bypass fix shipped with zero behavioural coverage; this file is that
coverage plus the env and nested-shell vectors.
"""
import importlib
import pathlib

import pytest

policy = importlib.import_module("ouroboros.git_shell_policy")

WS = pathlib.Path("/tmp/ws")
REPO = pathlib.Path("/Users/anton/Ouroboros/repo")
DATA = pathlib.Path("/Users/anton/Ouroboros/data")
ROOTS = [REPO, DATA]


def _violation(cmd, *, cwd="/tmp/ws", allow_network=True):
    return policy.external_workspace_git_violation(
        cmd, active_root=WS, cwd=cwd, protected_roots=ROOTS, allow_network=allow_network
    )


# --- bypasses that MUST be blocked -----------------------------------------

BLOCKED_CASES = [
    pytest.param("GIT_DIR=/Users/anton/Ouroboros/repo/.git git reset --hard", id="env_git_dir_bare"),
    pytest.param("env GIT_DIR=/Users/anton/Ouroboros/repo/.git git reset --hard", id="env_git_dir_wrapper"),
    pytest.param("GIT_WORK_TREE=/Users/anton/Ouroboros/repo git checkout .", id="env_work_tree"),
    pytest.param("cd /tmp/ws;git -C /Users/anton/Ouroboros/repo reset --hard", id="glued_semicolon_cd_minusC"),
    pytest.param("cd /tmp/ws\ngit -C /Users/anton/Ouroboros/repo reset --hard", id="newline_cd_minusC"),
    pytest.param("git -C /Users/anton/Ouroboros/repo status", id="direct_minusC_repo"),
    pytest.param("git --git-dir=/Users/anton/Ouroboros/repo/.git log", id="git_dir_flag_repo"),
    pytest.param("git --work-tree=/Users/anton/Ouroboros/data status", id="work_tree_flag_data"),
    pytest.param("sh -c 'git -C /Users/anton/Ouroboros/repo reset --hard'", id="nested_sh_c"),
    pytest.param("true && git -C /Users/anton/Ouroboros/repo clean -fd", id="glued_and_minusC"),
    pytest.param("cd /Users/anton/Ouroboros/repo && git status", id="cd_into_repo_then_git"),
]


@pytest.mark.parametrize("cmd", BLOCKED_CASES)
def test_runtime_targeting_git_is_blocked(cmd):
    assert _violation(cmd), f"expected BLOCK for: {cmd!r}"


def test_network_subcommand_blocked_when_network_disabled():
    assert _violation("git clone https://example.com/x.git", allow_network=False)


# --- legitimate external-workspace git that MUST stay allowed ---------------

ALLOWED_CASES = [
    pytest.param("git status", id="status"),
    pytest.param("git commit -m 'work'", id="commit"),
    pytest.param("git clone https://example.com/x.git", id="clone_network_on"),
    pytest.param("cd /tmp/ws/sub && git commit -m x", id="cd_subdir_commit"),
    pytest.param("git -C /tmp/ws/sub status", id="minusC_inside_workspace"),
    pytest.param("echo 'git -C /Users/anton/Ouroboros/repo' > note.txt", id="echo_mentions_git_not_a_git_cmd"),
    pytest.param("grep -r 'git reset' .", id="grep_mentions_git"),
]


@pytest.mark.parametrize("cmd", ALLOWED_CASES)
def test_legitimate_workspace_git_is_allowed(cmd):
    assert not _violation(cmd), f"expected ALLOW for: {cmd!r}"


def test_clone_allowed_when_network_enabled():
    assert not _violation("git clone https://example.com/x.git", allow_network=True)


# --- git remote read-only classifier (ibl-58871470f4ec) -------------------

REMOTE_READONLY_CASES = [
    pytest.param("git remote", id="remote_bare"),
    pytest.param("git remote -v", id="remote_verbose_short"),
    pytest.param("git remote --verbose", id="remote_verbose_long"),
    pytest.param("git remote get-url origin", id="remote_get_url"),
    pytest.param("git remote show", id="remote_show_bare"),
]

REMOTE_NETWORK_CASES = [
    pytest.param("git remote show origin", id="remote_show_named"),
]

REMOTE_MUTATING_CASES = [
    pytest.param("git remote add origin https://example.com/x.git", id="remote_add"),
    pytest.param("git remote remove origin", id="remote_remove"),
    pytest.param("git remote rm origin", id="remote_rm"),
    pytest.param("git remote rename origin upstream", id="remote_rename"),
    pytest.param("git remote set-url origin https://example.com/x.git", id="remote_set_url"),
    pytest.param("git remote prune origin", id="remote_prune"),
    pytest.param("git remote update", id="remote_update"),
]


@pytest.mark.parametrize("cmd", REMOTE_READONLY_CASES)
def test_git_remote_readonly_allowed(cmd):
    """Local read-only ``git remote`` forms must not be blocked."""
    reason = policy.run_shell_git_block_reason(cmd)
    assert reason == "", f"expected ALLOW for: {cmd!r}, got: {reason!r}"


@pytest.mark.parametrize("cmd", REMOTE_NETWORK_CASES)
def test_git_remote_show_named_network_gated(cmd):
    """``git remote show <name>`` contacts the remote — network-gated."""
    assert policy.run_shell_git_block_reason(cmd, allow_network=False)
    assert policy.run_shell_git_block_reason(cmd, allow_network=True) == ""


@pytest.mark.parametrize("cmd", REMOTE_MUTATING_CASES)
def test_git_remote_mutating_blocked(cmd):
    """Mutating ``git remote`` subcommands must always be blocked."""
    assert policy.run_shell_git_block_reason(cmd), f"expected BLOCK for: {cmd!r}"
