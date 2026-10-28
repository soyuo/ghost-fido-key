# CTAPHID channels and deadlines

The core allocator reserves `0xffffffff` for broadcast and never allocates
channel zero. Each active channel carries a deadline supplied by the caller;
`expire(now)` removes timed-out requests so platform adapters can emit the
protocol error and reclaim the channel without depending on an async runtime.
