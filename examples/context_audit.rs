//! Small, reproducible probes for context cancellation latency and chain costs.
//! Run with: cargo run --offline --locked --release --example context_audit
use rust_stdlib::context::{Context, Error};
use std::{
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

const CANCEL_RUNS: usize = 30;
const CANCEL_START_DELAY: Duration = Duration::from_millis(25);
const DEPTHS: [usize; 3] = [1_000, 2_000, 4_000];

fn main() {
    let (cancel_total_ns, cancel_max_ns) = cancellation_probe();
    let depths = depth_probe();
    let cancel_mean_ns = cancel_total_ns / CANCEL_RUNS as u128;

    print!(
        "{{\"cancellation\":{{\"runs\":{CANCEL_RUNS},\"start_delay_ms\":{},\"mean_observation_ns\":{cancel_mean_ns},\"max_observation_ns\":{cancel_max_ns}}},\"depths\":[",
        CANCEL_START_DELAY.as_millis()
    );
    for (index, result) in depths.iter().enumerate() {
        if index > 0 {
            print!(",");
        }
        print!(
            "{{\"depth\":{},\"build_ns\":{},\"check_ns\":{}}}",
            result.depth, result.build_ns, result.check_ns
        );
    }
    println!("]}}");
}

fn cancellation_probe() -> (u128, u128) {
    let mut total_ns = 0u128;
    let mut max_ns = 0u128;
    for _ in 0..CANCEL_RUNS {
        let (parent, cancel_parent) = Context::background().with_cancel();
        let (child, _cancel_child) = parent.with_cancel();
        let (started_tx, started_rx) = mpsc::channel();
        let waiter = thread::spawn(move || {
            started_tx.send(()).expect("signal waiter start");
            child.done().wait();
            child.err()
        });
        started_rx.recv().expect("waiter starts");
        thread::sleep(CANCEL_START_DELAY);

        let cancel_started = Instant::now();
        cancel_parent();
        let result = waiter.join().expect("waiter thread");
        assert_eq!(result, Some(Error::Canceled));

        let observed_ns = cancel_started.elapsed().as_nanos();
        total_ns += observed_ns;
        max_ns = max_ns.max(observed_ns);
    }
    (total_ns, max_ns)
}

struct DepthResult {
    depth: usize,
    build_ns: u128,
    check_ns: u128,
}

fn depth_probe() -> Vec<DepthResult> {
    DEPTHS
        .into_iter()
        .map(|depth| {
            let started = Instant::now();
            let mut context = Context::background();
            for _ in 0..depth {
                context = context.with_cancel().0;
            }
            let build_ns = started.elapsed().as_nanos();

            let started = Instant::now();
            context.check().expect("fresh chain is not cancelled");
            let check_ns = started.elapsed().as_nanos();
            DepthResult {
                depth,
                build_ns,
                check_ns,
            }
        })
        .collect()
}
