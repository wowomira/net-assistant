"""Reuse python-zeroconf on explicit manager interfaces, never expand scan scope."""
import asyncio

from app.discovery.types import safe_text


def names_for_scope(records, allowed):
    result = {}
    for record in records:
        server = safe_text(record.get("server", "").rstrip("."), 253)
        if not server:
            continue
        for address in record.get("addresses", []):
            if address in allowed:
                entry = {"hostname": server, "source": "mdns_server",
                         "service_instance": safe_text(record.get("name", ""), 253)}
                bucket = result.setdefault(address, [])
                if entry not in bucket and len(bucket) < 8:
                    bucket.append(entry)
    return result


async def collect_mdns(settings):
    if not settings.mdns_enabled:
        return {}
    from zeroconf import IPVersion, ServiceStateChange
    from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf
    from app.collectors.windows import collect_network

    local = await asyncio.to_thread(collect_network)
    local_addresses = {item.address for interface in local.interfaces for item in interface.addresses}
    if not settings.mdns_interface_addresses or not set(settings.mdns_interface_addresses) <= local_addresses:
        raise ValueError("mDNS requires explicitly approved addresses on manager interfaces.")
    zc = AsyncZeroconf(interfaces=settings.mdns_interface_addresses, ip_version=IPVersion.All)
    records, tasks = [], set()
    seen = set()

    async def resolve(service_type, name):
        info = AsyncServiceInfo(service_type, name)
        if await info.async_request(zc.zeroconf, settings.timeout_ms):
            records.append({"server": info.server, "name": name, "addresses": info.parsed_scoped_addresses()})

    def changed(zeroconf, service_type, name, state_change):
        if (state_change == ServiceStateChange.Removed or (service_type, name) in seen
                or len(seen) >= 200):
            return
        seen.add((service_type, name))
        task = asyncio.create_task(resolve(service_type, name))
        tasks.add(task)

    browser = AsyncServiceBrowser(zc.zeroconf, settings.mdns_service_types, handlers=[changed])
    browser_cancelled = False
    try:
        await asyncio.sleep(min(5, settings.timeout_ms / 1000 * 2))
        # Stop discovery before taking the finite resolver-task snapshot.
        browser_cancelled = True
        await browser.async_cancel()
        if tasks:
            await asyncio.gather(*tasks)
        return names_for_scope(records, set(settings.addresses()))
    finally:
        # python-zeroconf 0.154's cancellation is not idempotent.
        if not browser_cancelled:
            await browser.async_cancel()
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await zc.async_close()
