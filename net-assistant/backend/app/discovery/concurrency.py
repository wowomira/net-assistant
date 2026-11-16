"""Bounded asynchronous work pool shared by tool adapters."""
import asyncio


async def _pool(items, operation, concurrency):
    # Lazy iteration bounds memory even for an explicitly requested full TCP scan.
    iterator = iter(items)

    async def worker():
        while True:
            try:
                item = next(iterator)
            except StopIteration:
                return
            await operation(item)

    workers = [asyncio.create_task(worker()) for _ in range(concurrency)]
    try:
        await asyncio.gather(*workers)
    finally:
        for task in workers:
            if not task.done():
                task.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

