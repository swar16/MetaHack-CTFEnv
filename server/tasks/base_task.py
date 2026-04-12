"""
Base task definitions and shared milestone-evaluation helpers.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping
from urllib.parse import parse_qs, urlparse


@dataclass
class Milestone:
    """A progress milestone that triggers partial reward."""

    name: str
    description: str
    reward_value: float


@dataclass(frozen=True)
class MilestoneContext:
    """Evidence passed to a task-owned milestone evaluator."""

    action_name: str
    action_args: dict[str, Any]
    result: dict[str, Any]
    total_steps: int
    source_files_read: frozenset[str]
    endpoints_hit: Mapping[str, int]
    milestones_achieved: frozenset[str]

    @property
    def method(self) -> str:
        return str(self.action_args.get("method", "")).upper()

    @property
    def path(self) -> str:
        return str(self.action_args.get("path", ""))

    @property
    def path_without_query(self) -> str:
        return urlparse(self.path).path

    @property
    def query_params(self) -> dict[str, list[str]]:
        return parse_qs(urlparse(self.path).query)

    @property
    def endpoint_key(self) -> str:
        return f"{self.method} {self.path_without_query}".strip()

    @property
    def headers(self) -> dict[str, Any]:
        headers = self.action_args.get("headers", {})
        return headers if isinstance(headers, dict) else {}

    @property
    def body(self) -> dict[str, Any]:
        body = self.action_args.get("body", {})
        return body if isinstance(body, dict) else {}

    @property
    def file_path(self) -> str:
        return str(self.action_args.get("file_path", ""))

    @property
    def status_code(self) -> int:
        try:
            return int(self.result.get("status_code", 0))
        except (TypeError, ValueError, AttributeError):
            return 0

    @property
    def response_body(self) -> Any:
        if isinstance(self.result, dict):
            return self.result.get("body", {})
        return {}

    @property
    def response_dict(self) -> dict[str, Any]:
        return self.response_body if isinstance(self.response_body, dict) else {}

    @property
    def response_text(self) -> str:
        return _stringify(self.response_body)

    @property
    def request_text(self) -> str:
        return _stringify(
            {
                "path": self.path,
                "headers": self.headers,
                "body": self.body,
            }
        )


MilestoneEvaluator = Callable[[MilestoneContext, "BaseTask"], set[str]]


@dataclass
class BaseTask:
    """Base class for task definitions."""

    name: str
    display_name: str
    description: str
    difficulty: str  # "easy", "medium", "hard"
    flag: str
    optimal_steps: int
    relevant_files: list[str] = field(default_factory=list)
    vulnerable_endpoints: list[str] = field(default_factory=list)
    milestones: list[Milestone] = field(default_factory=list)
    hints: list[str] = field(default_factory=list)
    milestone_evaluator: MilestoneEvaluator | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary for observation metadata."""
        return {
            "task_name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "difficulty": self.difficulty,
            "optimal_steps": self.optimal_steps,
            "hints": self.hints[:1],  # Only first hint initially
        }

    def evaluate_milestones(self, context: MilestoneContext) -> set[str]:
        """Evaluate new milestones for a step."""
        if self.milestone_evaluator is None:
            return set()
        return self.milestone_evaluator(context, self)


def mark_source_read(context: MilestoneContext, task: BaseTask) -> set[str]:
    """Award source_read when an agent opens a task-relevant file."""
    if context.action_name != "view_source":
        return set()

    file_path = context.file_path
    if any(relevant == file_path or relevant in file_path for relevant in task.relevant_files):
        return {"source_read"}
    return set()


def response_has_flag(value: Any) -> bool:
    """Return True if the serialized value contains a flag-looking token."""
    return "FLAG{" in _stringify(value)


def response_user(context: MilestoneContext) -> dict[str, Any]:
    """Best-effort normalized user payload from a response."""
    body = context.response_dict
    user = body.get("user", body)
    return user if isinstance(user, dict) else {}


def request_uses_auth(context: MilestoneContext) -> bool:
    """Check whether a request included some auth material."""
    headers = {str(key).lower(): value for key, value in context.headers.items()}
    return bool(
        headers.get("authorization")
        or headers.get("x-api-key")
        or context.action_args.get("cookies")
        or "token" in context.query_params
        or "key" in context.query_params
    )


def body_contains_any(context: MilestoneContext, needles: list[str]) -> bool:
    """Check the serialized request for any case-insensitive substrings."""
    haystack = context.request_text.lower()
    return any(needle.lower() in haystack for needle in needles)


def _stringify(value: Any) -> str:
    """Deterministically stringify arbitrary values for rule checks."""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    except TypeError:
        return str(value)
