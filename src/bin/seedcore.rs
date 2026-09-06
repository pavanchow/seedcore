//! The Seedcore command line tool.
//!
//! It runs a scenario on the microkernel and prints the scheduling, IPC and
//! capability activity as it happens, followed by a summary. There are no
//! external dependencies, argument parsing included.

use seedcore::prelude::*;
use seedcore::scenario;
use seedcore::Kernel;
use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let command = args.first().map_or("demo", String::as_str);

    match command {
        "demo" => {
            run_and_print(scenario::demo(seed_from(&args, 1)), op_budget(256));
            ExitCode::SUCCESS
        }
        "run" => {
            let seed = seed_from(&args, 1);
            let pairs = flag(&args, "--pairs").and_then(|v| v.parse().ok()).unwrap_or(3);
            let burst = flag(&args, "--burst").and_then(|v| v.parse().ok()).unwrap_or(3);
            run_and_print(scenario::stress(seed, pairs, burst), op_budget(4096));
            ExitCode::SUCCESS
        }
        "delegate" => {
            demo_delegation();
            ExitCode::SUCCESS
        }
        "help" | "-h" | "--help" => {
            print_help();
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("seedcore: unknown command '{other}'\n");
            print_help();
            ExitCode::FAILURE
        }
    }
}

/// Demonstrate capability delegation and transitive revocation.
///
/// An owner holds full rights to a region. It delegates a copy to an editor, and
/// the editor sub delegates a read only copy to a viewer. Revoking the editor
/// capability then cascades: the viewer copy, derived from it, dies too, while
/// the owner keeps its own access.
fn demo_delegation() {
    let mut k = Kernel::new(1);
    let owner = k.create_task("owner");
    let editor = k.create_task("editor");
    let viewer = k.create_task("viewer");
    let region = k.create_region(owner, 8);

    let owner_th = k.spawn_thread(owner, "owner", 0, vec![]);
    let editor_th = k.spawn_thread(editor, "editor", 0, vec![]);
    let viewer_th = k.spawn_thread(viewer, "viewer", 0, vec![]);

    let root = k.grant(owner, ObjectRef::Region(region), Rights::READ | Rights::WRITE);
    let (editor_cap, er) = k.mint(owner, root, editor, Rights::NONE).unwrap();
    // The viewer copy drops the write right: delegation can only narrow.
    let (viewer_cap, vr) = k.mint(editor, editor_cap, viewer, Rights::WRITE).unwrap();

    println!("== capability delegation ==");
    println!("owner  holds region#{region} [{}] (root)", Rights::READ | Rights::WRITE);
    println!("editor holds a minted copy [{er}] derived from the owner");
    println!("viewer holds a minted copy [{vr}] derived from the editor (write dropped)");
    println!();

    println!("== access before revocation ==");
    report_access(&mut k, "owner", owner_th, root);
    report_access(&mut k, "editor", editor_th, editor_cap);
    report_access(&mut k, "viewer", viewer_th, viewer_cap);
    println!();

    let removed = k.revoke_tree(editor, editor_cap);
    println!("== revoke the editor capability (transitive) ==");
    println!("removed {removed} capabilities: the editor copy and everything derived from it");
    println!();

    println!("== access after revocation ==");
    report_access(&mut k, "owner", owner_th, root);
    report_access(&mut k, "editor", editor_th, editor_cap);
    report_access(&mut k, "viewer", viewer_th, viewer_cap);
}

fn report_access(k: &mut Kernel, who: &str, thread: seedcore::ThreadId, slot: CapSlot) {
    let read = if k.sys_read(thread, slot, 0).is_ok() { "read ok" } else { "read denied" };
    let write = if k.sys_write(thread, slot, 0, 1).is_ok() { "write ok" } else { "write denied" };
    println!("{who:<7} slot {slot}: {read}, {write}");
}

fn run_and_print(mut k: Kernel, max_ops: u64) {
    print_map(&k);
    println!("== trace ==");
    let report = k.run(max_ops);
    for event in k.trace() {
        println!("{event}");
    }
    println!();
    print_summary(&report);
}

fn print_map(k: &Kernel) {
    println!("== address spaces and capabilities ==");
    for task in k.tasks() {
        println!("task#{} {}", task.id, task.name);
        if task.caps.is_empty() {
            println!("    (no capabilities: cannot touch any kernel object)");
        }
        for (slot, cap) in task.caps.iter() {
            let note = match cap.object {
                ObjectRef::Region(_) => " <- address space",
                _ => "",
            };
            println!("    slot {slot}: {cap}{note}");
        }
    }
    println!();
}

fn print_summary(report: &RunReport) {
    println!("== summary ==");
    println!("ops executed      {}", report.ops_executed);
    println!("context switches  {}", report.context_switches);
    println!("final tick        {}", report.final_tick);
    println!("IPC rendezvous    {}", report.rendezvous);
    println!("cap transfers     {}", report.cap_transfers);
    println!("memory reads      {}", report.mem_reads);
    println!("memory writes     {}", report.mem_writes);
    println!("denied syscalls   {}", report.denials);
    if report.deadlocked {
        println!("note: run ended with threads still blocked (no progress possible)");
    }
}

fn print_help() {
    println!(
        "seedcore: a deterministic microkernel simulator

usage:
  seedcore demo [--seed N]
      Run the guided demo: user space filesystem and console services, a
      client that reads a file over IPC and prints, capability transfer, and
      two denied unauthorized accesses.

  seedcore run [--seed N] [--pairs N] [--burst N]
      Run a randomized producer and consumer stress scenario plus a rogue task
      whose every access is denied.

  seedcore delegate
      Show capability delegation and transitive revocation: an owner delegates a
      region to an editor, the editor sub delegates a read only copy to a viewer,
      and revoking the editor capability cascades to the derived viewer copy.

  seedcore help
      Show this message.

environment:
  SEEDCORE_FUZZ_OPS   cap on the number of ops executed (overrides the default)

everything is a pure function of the seed. the same seed prints the same trace."
    );
}

fn seed_from(args: &[String], default: u64) -> u64 {
    flag(args, "--seed")
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn op_budget(default: u64) -> u64 {
    env::var("SEEDCORE_FUZZ_OPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let pos = args.iter().position(|a| a == name)?;
    args.get(pos + 1).map(String::as_str)
}
