"""Stop Phase 3 billable features after a monthly AWS budget alert."""

from __future__ import annotations

import os
from typing import Any

import boto3


class KillSwitchError(ValueError):
    """A budget event or kill-switch action was invalid or unavailable."""


def _validate_budget_event(event: Any, expected_topic_arn: str) -> None:
    records = event.get("Records") if isinstance(event, dict) else None
    if (
        not isinstance(records, list)
        or len(records) != 1
        or not isinstance(records[0], dict)
        or records[0].get("EventSource") != "aws:sns"
    ):
        raise KillSwitchError("budget event is invalid")
    sns = records[0].get("Sns")
    if (
        not isinstance(sns, dict)
        or sns.get("Type") != "Notification"
        or sns.get("TopicArn") != expected_topic_arn
        or not isinstance(sns.get("Message"), str)
        or len(sns["Message"]) > 262_144
    ):
        raise KillSwitchError("budget event is invalid")


def _disable_schedule(scheduler: Any, *, name: str, group: str) -> None:
    schedule = scheduler.get_schedule(Name=name, GroupName=group)
    if schedule.get("State") == "DISABLED":
        return

    request = {
        "Name": name,
        "GroupName": group,
        "State": "DISABLED",
        "ScheduleExpression": schedule["ScheduleExpression"],
        "FlexibleTimeWindow": schedule["FlexibleTimeWindow"],
        "Target": schedule["Target"],
    }
    for key in (
        "ScheduleExpressionTimezone",
        "StartDate",
        "EndDate",
        "Description",
        "KmsKeyArn",
        "ActionAfterCompletion",
    ):
        if key in schedule:
            request[key] = schedule[key]
    scheduler.update_schedule(**request)


def _stop_running_executions(stepfunctions: Any, *, state_machine_arn: str) -> None:
    next_token = None
    stop_failed = False
    while True:
        request = {
            "stateMachineArn": state_machine_arn,
            "statusFilter": "RUNNING",
            "maxResults": 1000,
        }
        if next_token:
            request["nextToken"] = next_token
        response = stepfunctions.list_executions(**request)
        for execution in response.get("executions", []):
            execution_arn = execution.get("executionArn")
            if execution_arn:
                try:
                    stepfunctions.stop_execution(
                        executionArn=execution_arn,
                        cause="AWS monthly cost circuit breaker",
                    )
                except Exception:
                    stop_failed = True
        next_token = response.get("nextToken")
        if not next_token:
            break
    if stop_failed:
        raise RuntimeError("one or more scan executions could not be stopped")


def _stop_running_tasks(ecs: Any, *, cluster_arn: str) -> None:
    next_token = None
    stop_failed = False
    while True:
        request = {"cluster": cluster_arn, "desiredStatus": "RUNNING"}
        if next_token:
            request["nextToken"] = next_token
        response = ecs.list_tasks(**request)
        for task_arn in response.get("taskArns", []):
            try:
                ecs.stop_task(
                    cluster=cluster_arn,
                    task=task_arn,
                    reason="AWS monthly cost circuit breaker",
                )
            except Exception:
                stop_failed = True
        next_token = response.get("nextToken")
        if not next_token:
            break
    if stop_failed:
        raise RuntimeError("one or more scan tasks could not be stopped")


def disable_live_features(
    event: Any,
    *,
    table: Any,
    expected_topic_arn: str,
    scheduler: Any | None = None,
    scan_schedule_name: str = "",
    scan_schedule_group: str = "default",
    stepfunctions: Any | None = None,
    scan_state_machine_arn: str = "",
    ecs: Any | None = None,
    scan_cluster_arn: str = "",
) -> dict[str, str]:
    """Disable Rin and stop scheduled or in-flight Phase 3 scan work.

    Each action is attempted even if another one fails, so a table or AWS API
    error does not prevent the remaining cost controls from running.
    """
    _validate_budget_event(event, expected_topic_arn)
    failures = []

    try:
        table.update_item(
            Key={"pk": "PLATFORM", "sk": "CONFIG"},
            UpdateExpression="SET rin_enabled = :disabled, static_mode = :enabled",
            ConditionExpression="attribute_exists(pk) AND attribute_exists(sk)",
            ExpressionAttributeValues={":disabled": False, ":enabled": True},
        )
    except Exception:
        failures.append("feature flags")

    if scheduler is not None and scan_schedule_name:
        try:
            _disable_schedule(
                scheduler,
                name=scan_schedule_name,
                group=scan_schedule_group,
            )
        except Exception:
            failures.append("scan schedule")

    if stepfunctions is not None and scan_state_machine_arn:
        try:
            _stop_running_executions(
                stepfunctions,
                state_machine_arn=scan_state_machine_arn,
            )
        except Exception:
            failures.append("scan executions")

    if ecs is not None and scan_cluster_arn:
        try:
            _stop_running_tasks(ecs, cluster_arn=scan_cluster_arn)
        except Exception:
            failures.append("scan tasks")

    if failures:
        raise KillSwitchError("one or more Phase 3 cost controls could not be applied")
    return {"status": "DISABLED"}


def lambda_handler(event: Any, context: Any) -> dict[str, str]:
    """SNS-triggered budget breaker; never logs or returns the event body."""
    del context
    topic_arn = os.environ.get("PHASE3_BUDGET_KILL_TOPIC_ARN", "").strip()
    table_name = os.environ.get("PHASE3_FEATURE_TABLE", "").strip()
    schedule_name = os.environ.get("PHASE3_SCAN_SCHEDULE_NAME", "").strip()
    state_machine_arn = os.environ.get("PHASE3_SCAN_STATE_MACHINE_ARN", "").strip()
    cluster_arn = os.environ.get("PHASE3_SCAN_ECS_CLUSTER_ARN", "").strip()
    region = os.environ.get("AWS_REGION", "").strip()
    if not all((topic_arn, table_name, schedule_name, state_machine_arn, cluster_arn, region)):
        raise KillSwitchError("kill switch is not configured")

    try:
        session = boto3.session.Session(region_name=region)
        table = session.resource("dynamodb").Table(table_name)
        scheduler = session.client("scheduler")
        stepfunctions = session.client("stepfunctions")
        ecs = session.client("ecs")
    except Exception:
        raise KillSwitchError("live features could not be disabled") from None

    return disable_live_features(
        event,
        table=table,
        expected_topic_arn=topic_arn,
        scheduler=scheduler,
        scan_schedule_name=schedule_name,
        stepfunctions=stepfunctions,
        scan_state_machine_arn=state_machine_arn,
        ecs=ecs,
        scan_cluster_arn=cluster_arn,
    )
