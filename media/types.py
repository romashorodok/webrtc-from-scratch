import itertools
import time


def tick(interval_ns, initial_wait=False):
    start = time.perf_counter_ns()

    if not initial_wait:
        yield

    for i in itertools.count(1):
        current_time = time.perf_counter_ns()
        next_tick_time = start + i * interval_ns
        sleep_duration = (next_tick_time - current_time) / 1e9

        if sleep_duration > 0:
            time.sleep(sleep_duration)

        yield
