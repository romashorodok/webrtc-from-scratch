"""Configuration shared by native selection and the Python reference loop."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LoopConfig:
    packet_workers: int = 0
    packet_queue_capacity: int = 2048
    receive_packet_budget: int = 32
    receive_time_budget_us: int = 100
    command_capacity: int = 4096

    def __post_init__(self) -> None:
        if self.packet_workers < 0:
            raise ValueError("packet_workers must not be negative")
        for name in (
            "packet_queue_capacity",
            "receive_packet_budget",
            "receive_time_budget_us",
            "command_capacity",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")

    def factory_arguments(self) -> dict[str, int]:
        return {
            "packet_workers": self.packet_workers,
            "packet_queue_capacity": self.packet_queue_capacity,
            "receive_packet_budget": self.receive_packet_budget,
            "receive_time_budget_us": self.receive_time_budget_us,
        }
