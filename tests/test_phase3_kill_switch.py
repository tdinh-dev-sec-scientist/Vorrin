from __future__ import annotations

import json

import pytest

from phase3.kill_switch import KillSwitchError, disable_live_features

TOPIC = "arn:aws:sns:us-east-1:123456789012:phase3-budget-kill"


def _event(*, topic=TOPIC, message="budget threshold crossed"):
    return {
        "Records": [
            {
                "EventSource": "aws:sns",
                "Sns": {"Type": "Notification", "TopicArn": topic, "Message": message},
            }
        ]
    }


class Table:
    def __init__(self):
        self.updates = []

    def update_item(self, **kwargs):
        self.updates.append(kwargs)


def test_budget_kill_switch_atomically_disables_rin_and_selects_static_mode():
    table = Table()

    result = disable_live_features(_event(), table=table, expected_topic_arn=TOPIC)

    assert result == {"status": "DISABLED"}
    assert len(table.updates) == 1
    update = table.updates[0]
    assert update["Key"] == {"pk": "PLATFORM", "sk": "CONFIG"}
    assert update["ConditionExpression"] == "attribute_exists(pk) AND attribute_exists(sk)"
    assert "rin_enabled = :disabled" in update["UpdateExpression"]
    assert "static_mode = :enabled" in update["UpdateExpression"]
    assert update["ExpressionAttributeValues"] == {":disabled": False, ":enabled": True}


@pytest.mark.parametrize(
    "event",
    [
        {},
        {"Records": []},
        _event(topic="arn:aws:sns:us-east-1:999999999999:other"),
        {"Records": [{"EventSource": "aws:sqs", "Sns": {}}]},
        _event(message="x" * 262_145),
        {
            "Records": [
                {
                    "EventSource": "aws:sns",
                    "Sns": {"Type": "SubscriptionConfirmation", "TopicArn": TOPIC, "Message": "x"},
                }
            ]
        },
    ],
)
def test_kill_switch_rejects_untrusted_or_oversized_events_without_writes(event):
    table = Table()

    with pytest.raises(KillSwitchError):
        disable_live_features(event, table=table, expected_topic_arn=TOPIC)

    assert table.updates == []


def test_kill_switch_error_does_not_echo_budget_message():
    class FailingTable:
        def update_item(self, **_kwargs):
            raise RuntimeError("private-backend-error")

    with pytest.raises(KillSwitchError) as exc:
        disable_live_features(
            _event(message=json.dumps({"secret": "do-not-echo"})),
            table=FailingTable(),
            expected_topic_arn=TOPIC,
        )

    assert "do-not-echo" not in str(exc.value)
    assert "private-backend-error" not in str(exc.value)


class Scheduler:
    def __init__(self):
        self.updated = []
        self.schedule = {
            "State": "ENABLED",
            "ScheduleExpression": "rate(6 hours)",
            "ScheduleExpressionTimezone": "UTC",
            "FlexibleTimeWindow": {"Mode": "OFF"},
            "Target": {"Arn": "scan-state-machine", "RoleArn": "scheduler-role", "Input": "{}"},
        }

    def get_schedule(self, **_kwargs):
        return self.schedule

    def update_schedule(self, **kwargs):
        self.updated.append(kwargs)


class StepFunctions:
    def __init__(self):
        self.stopped = []

    def list_executions(self, **kwargs):
        assert kwargs["statusFilter"] == "RUNNING"
        return {"executions": [{"executionArn": "scan-execution"}]}

    def stop_execution(self, **kwargs):
        self.stopped.append(kwargs)


class ECS:
    def __init__(self):
        self.stopped = []

    def list_tasks(self, **kwargs):
        assert kwargs["desiredStatus"] == "RUNNING"
        return {"taskArns": ["scan-task"]}

    def stop_task(self, **kwargs):
        self.stopped.append(kwargs)


def test_budget_breaker_disables_schedule_and_stops_running_scan_work():
    table = Table()
    scheduler = Scheduler()
    stepfunctions = StepFunctions()
    ecs = ECS()

    result = disable_live_features(
        _event(),
        table=table,
        expected_topic_arn=TOPIC,
        scheduler=scheduler,
        scan_schedule_name="phase3-scan",
        stepfunctions=stepfunctions,
        scan_state_machine_arn="scan-state-machine",
        ecs=ecs,
        scan_cluster_arn="scan-cluster",
    )

    assert result == {"status": "DISABLED"}
    assert scheduler.updated[0]["State"] == "DISABLED"
    assert scheduler.updated[0]["ScheduleExpression"] == "rate(6 hours)"
    assert scheduler.updated[0]["Target"]["RoleArn"] == "scheduler-role"
    assert stepfunctions.stopped == [
        {"executionArn": "scan-execution", "cause": "AWS monthly cost circuit breaker"}
    ]
    assert ecs.stopped == [
        {
            "cluster": "scan-cluster",
            "task": "scan-task",
            "reason": "AWS monthly cost circuit breaker",
        }
    ]
    assert len(table.updates) == 1


def test_breaker_attempts_other_controls_when_one_service_fails():
    class FailingScheduler(Scheduler):
        def get_schedule(self, **_kwargs):
            raise RuntimeError("sensitive scheduler detail")

    table = Table()
    stepfunctions = StepFunctions()
    ecs = ECS()

    with pytest.raises(KillSwitchError) as exc:
        disable_live_features(
            _event(),
            table=table,
            expected_topic_arn=TOPIC,
            scheduler=FailingScheduler(),
            scan_schedule_name="phase3-scan",
            stepfunctions=stepfunctions,
            scan_state_machine_arn="scan-state-machine",
            ecs=ecs,
            scan_cluster_arn="scan-cluster",
        )

    assert len(table.updates) == 1
    assert len(stepfunctions.stopped) == 1
    assert len(ecs.stopped) == 1
    assert "sensitive scheduler detail" not in str(exc.value)
