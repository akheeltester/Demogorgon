"""Controller — orchestrates the entire hunt.

Executive Controller: sits between LLM and tools.
Tool Selection: maps vulnerability classes to executors.
Execution Graph: goal-driven execution replacing iteration loops.
Self-Evaluator: calculates progress after every experiment.
"""

from sentinel_v2.controller.executive import ExecutiveController, Hypothesis, Experiment
from sentinel_v2.controller.tool_selection import (
    get_executor_spec, get_executor_by_name, list_executors,
    EXECUTOR_REGISTRY, ExecutorSpec,
)
from sentinel_v2.controller.execution_graph import ExecutionGraph, GraphNode
from sentinel_v2.controller.self_evaluator import SelfEvaluator, EvalResult

__all__ = [
    "ExecutiveController", "Hypothesis", "Experiment",
    "get_executor_spec", "get_executor_by_name", "list_executors",
    "EXECUTOR_REGISTRY", "ExecutorSpec",
    "ExecutionGraph", "GraphNode",
    "SelfEvaluator", "EvalResult",
]
