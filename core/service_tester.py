"""Concurrent TCP/UDP observation using a process-shared thread pool. TCP connects, records pre-payload banners, sends the payload and records post-send bytes. UDP has only a post-send phase. Post-send arrival is a timing fact, not proof of causation."""

import socket
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

def _normalize_services(services: Dict[str, tuple]) -> Dict[str, Tuple[str, int, str]]:
    """Normalize services dict to (host, port, transport) triples."""
    result = {}
    for name, svc in services.items():
        if len(svc) == 2:
            result[name] = (svc[0], svc[1], "tcp")
        else:
            result[name] = (svc[0], svc[1], svc[2])
    return result

# ============================================================================
# Process-wide shared thread pool (anti-OOM)
#

#

# ============================================================================
_shared_pool: Optional[ThreadPoolExecutor] = None
_shared_pool_size: int = 0

def get_shared_pool(min_workers: int) -> ThreadPoolExecutor:
    """Reuse the process-wide thread pool and grow it only when required."""
    global _shared_pool, _shared_pool_size
    want = max(1, int(min_workers))
    if _shared_pool is None or _shared_pool_size < want:
        if _shared_pool is not None:
            _shared_pool.shutdown(wait=False, cancel_futures=True)
        _shared_pool_size = want
        _shared_pool = ThreadPoolExecutor(max_workers=want)
        logger.debug(
            f"[SHARED-POOL] created size={_shared_pool_size} pid={os.getpid()}"
        )
    return _shared_pool

def shutdown_shared_pool() -> None:
    """Shut down the shared worker thread pool."""
    global _shared_pool, _shared_pool_size
    if _shared_pool is not None:
        _shared_pool.shutdown(wait=False)
        _shared_pool = None
        _shared_pool_size = 0

@dataclass
class ServiceResponse:
    """One service observation split at the payload-send boundary.

    ``response_bytes`` remains the legacy compatibility field.  It contains
    bytes observed after sending the payload when available, otherwise the
    pre-payload banner.  ``post_payload`` is a temporal schema label; a delayed
    greeting can arrive in that phase.  Feedback code must inspect
    ``response_phase`` or ``payload_bytes`` and must not infer semantic
    causation from the label alone.
    """
    service_name: str
    response_bytes: bytes
    latency_ms: float
    timestamp: float
    response_phase: str = "post_payload"
    banner_bytes: bytes = b""
    banner_latency_ms: float = 0.0
    payload_latency_ms: float = 0.0

    @property
    def payload_bytes(self) -> bytes:
        return self.response_bytes if self.response_phase == "post_payload" else b""

    @property
    def has_payload_response(self) -> bool:
        return bool(self.payload_bytes)

    @property
    def has_banner(self) -> bool:
        return bool(self.banner_bytes) or (
            self.response_phase == "pre_payload_banner" and bool(self.response_bytes)
        )

class ServiceTester:
    """Tests packets against local services concurrently."""

    def __init__(
        self,
        services: Dict[str, tuple],
        timeout: float = 5.0,
        banner_timeout: Optional[float] = None,
    ):
        self.services = _normalize_services(services)
        self.timeout = timeout

        banner_value = timeout if banner_timeout is None else banner_timeout
        self.banner_timeout = min(banner_value, timeout)

    def test_packet(self, packet: bytes) -> List[ServiceResponse]:
        """Test a single packet against all services concurrently."""
        if not self.services:
            return []

        responses = []
        pool = get_shared_pool(len(self.services))

        futures = {
            pool.submit(
                self._send_and_receive, name, host, port, transport, packet
            ): name
            for name, (host, port, transport) in self.services.items()
        }
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    responses.append(result)
            except Exception as e:
                logger.debug(f"Service error for {futures[future]}: {e}")

        return responses

    def test_packets_parallel(
        self,
        packets: List[bytes],
        max_workers: int = 64,
        batch_size: int = 500,
    ) -> List[List[ServiceResponse]]:
        """Test multiple packets against all services concurrently in batches."""
        if not packets:
            return []

        all_results: List[List[ServiceResponse]] = [[] for _ in range(len(packets))]
        pool = get_shared_pool(max_workers)  

        for start in range(0, len(packets), batch_size):
            batch = packets[start:start + batch_size]
            batch_offset = start
            batch_results: List[List[ServiceResponse]] = [[] for _ in range(len(batch))]

            futures = {}
            for i, packet in enumerate(batch):
                for name, (host, port, transport) in self.services.items():
                    future = pool.submit(
                        self._send_and_receive, name, host, port, transport, packet
                    )
                    futures[future] = i

            for future in as_completed(futures):
                idx = futures[future]
                try:
                    result = future.result()
                    if result:
                        batch_results[idx].append(result)
                except Exception as e:
                    logger.debug(f"Service error: {e}")

            for i in range(len(batch)):
                all_results[batch_offset + i] = batch_results[i]

        return all_results

    # ------------------------------------------------------------------
    # Phase-aware TCP send/receive
    # ------------------------------------------------------------------

    def _send_tcp(
        self,
        service_name: str,
        host: str,
        port: int,
        packet: bytes,
        start_time: float,
    ) -> Optional[ServiceResponse]:
        """TCP: connect → observe banner → send payload → observe response.

        A banner no longer short-circuits the payload send.  This separates
        passive identification from bytes observed after the payload send.
        The phase boundary is temporal evidence, not proof that the payload
        semantically caused every byte received after it.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect((host, port))

            banner = b""
            banner_latency = 0.0
            connection_open = True
            banner_deadline = time.monotonic() + self.banner_timeout
            while len(banner) < 8192:
                remaining = banner_deadline - time.monotonic()
                if remaining <= 0.0:
                    break
                sock.settimeout(remaining)
                try:
                    chunk = sock.recv(8192 - len(banner))
                except socket.timeout:
                    break
                if not chunk:
                    connection_open = False
                    break
                if not banner:
                    banner_latency = (time.time() - start_time) * 1000
                banner += chunk

            # A peer may send a greeting and immediately close.  Sending is no
            # longer possible, but the pre-payload fact remains reportable.
            if not connection_open:
                if not banner:
                    return None
                return ServiceResponse(
                    service_name=service_name,
                    response_bytes=banner,
                    latency_ms=banner_latency,
                    timestamp=time.time(),
                    response_phase="pre_payload_banner",
                    banner_bytes=banner,
                    banner_latency_ms=banner_latency,
                )

            sock.settimeout(self.timeout)
            response = b""
            payload_start = time.time()
            try:
                sock.sendall(packet)
                response = sock.recv(8192)
            except (socket.timeout, BrokenPipeError, ConnectionResetError):
                response = b""

            if not response and not banner:
                return None

            now = time.time()
            payload_latency = (now - payload_start) * 1000 if response else 0.0
            total_latency = (now - start_time) * 1000 if response else banner_latency
            return ServiceResponse(
                service_name=service_name,
                response_bytes=response if response else banner,
                latency_ms=total_latency,
                timestamp=now,
                response_phase=("post_payload" if response else "pre_payload_banner"),
                banner_bytes=banner,
                banner_latency_ms=banner_latency,
                payload_latency_ms=payload_latency,
            )

    # ------------------------------------------------------------------
    # UDP send/receive
    # ------------------------------------------------------------------

    def _send_udp(
        self,
        service_name: str,
        host: str,
        port: int,
        packet: bytes,
        start_time: float,
    ) -> Optional[ServiceResponse]:
        """UDP: sendto → recvfrom (no connection, no banner)."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.timeout)
            sock.sendto(packet, (host, port))
            try:
                response, _ = sock.recvfrom(8192)
                if response:
                    latency = (time.time() - start_time) * 1000
                    return ServiceResponse(
                        service_name=service_name,
                        response_bytes=response,
                        latency_ms=latency,
                        timestamp=time.time(),
                        response_phase="post_payload",
                        payload_latency_ms=latency,
                    )
            except socket.timeout:
                pass
        return None

    # ------------------------------------------------------------------
    # Unified dispatcher
    # ------------------------------------------------------------------

    def _send_and_receive(
        self,
        service_name: str,
        host: str,
        port: int,
        transport: str,
        packet: bytes,
    ) -> Optional[ServiceResponse]:
        """Route to TCP or UDP sender based on transport."""
        start_time = time.time()

        try:
            if transport == "udp":
                return self._send_udp(service_name, host, port, packet, start_time)
            else:
                return self._send_tcp(service_name, host, port, packet, start_time)
        except socket.timeout:
            return None
        except Exception as e:
            logger.debug(f"Connection error for {service_name}: {e}")
            return None
