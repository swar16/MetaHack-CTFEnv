"""
Typed response models for the CTF environment.

FastMCP generates runtime schemas for tool calls, but these models keep the
environment contract explicit and make the public response shapes easier to
reason about, validate, and document.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ErrorResponse(BaseModel):
    """Generic error response."""

    error: str
    details: dict[str, Any] | None = None


class TaskInfoModel(BaseModel):
    """Public task metadata returned to agents."""

    task_name: str
    display_name: str
    description: str
    difficulty: str
    optimal_steps: int
    hints: list[str] = Field(default_factory=list)


class SourceFileListResponseModel(BaseModel):
    """Response returned by list_source_files()."""

    files: list[str] = Field(default_factory=list)
    task_relevant_files: list[str] = Field(default_factory=list)


class SourceViewResponseModel(BaseModel):
    """Response returned by view_source()."""

    file_path: str
    content: str
    lines: int


class HttpRequestResponseModel(BaseModel):
    """Normalized HTTP proxy response returned by http_request()."""

    status_code: int
    headers: dict[str, Any] = Field(default_factory=dict)
    body: Any = None
    cookies: dict[str, Any] = Field(default_factory=dict)


class GradeSummaryModel(BaseModel):
    """Deterministic grading breakdown for a completed episode."""

    task: str
    difficulty: str
    final_score: float
    flag_captured: bool
    milestones_achieved: list[str] = Field(default_factory=list)
    milestones_missed: list[str] = Field(default_factory=list)
    total_steps: int
    optimal_steps: int
    noise_count: int
    elegance_bonus: float
    precision_bonus: float
    noise_penalty: float
    detection_risk: float


class FlagSubmissionResponseModel(BaseModel):
    """Response returned by submit_flag()."""

    correct: bool
    message: str
    score: float
    grade_summary: GradeSummaryModel | dict[str, Any] = Field(default_factory=dict)


class TaskReadyResponseModel(BaseModel):
    """Response returned by start_task()."""

    status: str
    message: str
    task: TaskInfoModel
    instructions: str
