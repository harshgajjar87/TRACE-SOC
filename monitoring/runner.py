"""TRACE-SOC continuous Windows endpoint monitoring runner."""

import argparse
import signal
import threading
import time

from pathlib import Path

from collectors.windows_event_collector import (
    DEFAULT_CHANNELS,
    collect_windows_events,
)

from monitoring.engine import (
    create_monitoring_schema,
    record_monitoring_run,
    start_service,
    update_service_status,
    utc_now,
)


stop_event = threading.Event()


def run_monitoring_cycle(
    channels=None,
    max_events=500,
    state_file=None,
    collector_function=None,
):
    """Execute one polling cycle, record its result, then run analysis."""
    channels = channels or DEFAULT_CHANNELS
    collector = collector_function or collect_windows_events

    started_at = utc_now()

    try:
        kwargs = {
            "channels": channels,
            "max_events": max_events,
        }

        if state_file is not None:
            kwargs["state_file"] = Path(state_file)

        summary = collector(**kwargs)

        record_monitoring_run(
            status="SUCCESS",
            summary=summary,
            started_at=started_at,
        )

        # Run automated analysis after successful collection.
        # Analysis failures are recorded separately and do not
        # mark a successful collection as failed.
        try:
            from monitoring.analysis_pipeline import run_analysis_pipeline
            analysis_result = run_analysis_pipeline()
            summary["analysis"] = analysis_result
        except Exception as analysis_exc:
            summary["analysis"] = {
                "status": "FAILED",
                "error": str(analysis_exc),
            }

        return summary

    except Exception as exc:
        record_monitoring_run(
            status="FAILED",
            error_message=str(exc)[:2000],
            started_at=started_at,
        )
        raise


def run_continuous_monitoring(
    channels=None,
    polling_interval_seconds=60,
    max_events=500,
    state_file=None,
    collector_function=None,
    max_cycles=None,
):
    """
    Poll Windows Event Logs repeatedly.

    max_cycles is useful for automated testing.
    Leave it as None for continuous operation.
    """
    if polling_interval_seconds < 1:
        raise ValueError("Polling interval must be at least 1 second.")

    if max_events < 1:
        raise ValueError("max_events must be at least 1.")

    channels = channels or DEFAULT_CHANNELS

    create_monitoring_schema()
    start_service(polling_interval_seconds)
    stop_event.clear()

    cycle_count = 0

    print("\nTRACE-SOC CONTINUOUS MONITORING STARTED")
    print("Channels:", ", ".join(channels))
    print("Polling interval:", polling_interval_seconds, "seconds")
    print("Press CTRL+C to stop.\n")

    try:
        while not stop_event.is_set():
            cycle_started = time.monotonic()

            try:
                summary = run_monitoring_cycle(
                    channels=channels,
                    max_events=max_events,
                    state_file=state_file,
                    collector_function=collector_function,
                )

                print(
                    "[SUCCESS] "
                    f"Received={summary['total_received']} | "
                    f"Inserted={summary['total_inserted']} | "
                    f"Duplicates={summary['total_duplicates']}"
                )

            except Exception as exc:
                print(f"[ERROR] Collection cycle failed: {exc}")

            cycle_count += 1

            if max_cycles is not None and cycle_count >= max_cycles:
                break

            elapsed = time.monotonic() - cycle_started
            remaining = max(0, polling_interval_seconds - elapsed)

            # Event.wait allows CTRL+C or another stop request to
            # interrupt the waiting period.
            stop_event.wait(remaining)

    finally:
        update_service_status("STOPPED")
        print("\nTRACE-SOC monitoring stopped.")

    return cycle_count


def handle_stop_signal(signum, frame):
    print("\nStop requested. Finishing current collection cycle...")
    stop_event.set()


def main():
    parser = argparse.ArgumentParser(
        description="TRACE-SOC Continuous Monitoring Service"
    )

    parser.add_argument(
        "--channels",
        nargs="+",
        default=DEFAULT_CHANNELS,
    )

    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Polling interval in seconds. Default: 60.",
    )

    parser.add_argument(
        "--max-events",
        type=int,
        default=500,
    )

    parser.add_argument(
        "--state-file",
        default=None,
        help="Optional override for the collector state file.",
    )

    args = parser.parse_args()

    signal.signal(signal.SIGINT, handle_stop_signal)

    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handle_stop_signal)

    try:
        run_continuous_monitoring(
            channels=args.channels,
            polling_interval_seconds=args.interval,
            max_events=args.max_events,
            state_file=args.state_file,
        )
    except Exception as exc:
        update_service_status(
            "ERROR",
            last_error=str(exc)[:2000],
        )
        raise SystemExit(f"Monitoring service failed: {exc}")


if __name__ == "__main__":
    main()
