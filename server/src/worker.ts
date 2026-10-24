/**
 * The worker loop: what happens after answers are given. Every second, and at once when woken, it runs a
 * pass (arrivals offered, inbox events told, part fetches and deliveries started); it sweeps retention
 * every ten minutes. It runs in the server's process by default.
 */
export interface Worker {
  /** Run a pass soon. */
  wake(): void;
  /** Stop the loop and wait for the pass underway. */
  stop(): Promise<void>;
}

export function startWorker(
  pass: () => Promise<void>,
  sweep: () => Promise<void>,
  log: (error: unknown) => void,
  opts: { intervalMs?: number; sweepMs?: number } = {},
): Worker {
  let running: Promise<void> | null = null;
  let again = false;
  let stopped = false;

  const run = () => {
    if (stopped) return;
    if (running) return void (again = true);
    running = pass()
      .catch(log)
      .finally(() => {
        running = null;
        if (again) {
          again = false;
          run();
        }
      });
  };
  const interval = setInterval(run, opts.intervalMs ?? 1000);
  const sweeper = setInterval(() => void sweep().catch(log), opts.sweepMs ?? 10 * 60_000);
  interval.unref();
  sweeper.unref();

  return {
    wake: () => setImmediate(run),
    async stop() {
      stopped = true;
      clearInterval(interval);
      clearInterval(sweeper);
      await running;
    },
  };
}
