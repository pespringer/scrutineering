"""The remediation lifecycle allows only the documented transitions."""

import pytest

from src.db.models import RemediationStatus as S
from src.remediation.state_machine import LABELS, TERMINAL, TRANSITIONS, InvalidRemediationTransition, transition

HAPPY_PATH = [S.PROPOSED, S.APPROVED, S.BUILDING, S.VERIFYING, S.READY, S.COMPLETED]


def test_the_happy_path_is_a_chain_of_legal_steps():
    for current, target in zip(HAPPY_PATH, HAPPY_PATH[1:]):
        assert transition(current, target) == target


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (S.VERIFYING, S.NEEDS_ACCEPTANCE),
        (S.NEEDS_ACCEPTANCE, S.READY),
        (S.BUILDING, S.FAILED),
        (S.FAILED, S.PROPOSED),
        (S.PROPOSED, S.CANCELLED),
        (S.READY, S.CANCELLED),
    ],
)
def test_side_paths_are_allowed(current, target):
    assert transition(current, target) == target


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (S.PROPOSED, S.BUILDING),  # must be approved first
        (S.APPROVED, S.READY),  # must be built and verified
        (S.VERIFYING, S.COMPLETED),  # completion needs a rescan of the real image
        (S.NEEDS_ACCEPTANCE, S.COMPLETED),
        (S.COMPLETED, S.PROPOSED),
        (S.CANCELLED, S.PROPOSED),
    ],
)
def test_shortcuts_are_rejected(current, target):
    with pytest.raises(InvalidRemediationTransition):
        transition(current, target)


def test_every_status_has_rules_and_a_label():
    assert set(TRANSITIONS) == set(S) == set(LABELS)
    assert TRANSITIONS[S.COMPLETED] == TRANSITIONS[S.CANCELLED] == frozenset()
    assert S.FAILED in TERMINAL and transition(S.FAILED, S.FAILED) == S.FAILED
