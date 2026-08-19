# app/wazuh_client.py
import logging
import os
import queue as _queue
import threading
from typing import Generator, List, Dict, Any, Tuple, Optional

import requests
import urllib3
from requests.auth import HTTPBasicAuth
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
    before_sleep_log,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)

VULN_INDEX = "wazuh-states-vulnerabilities-*"
SCROLL_TTL = "2m"
BATCH_SIZE = 10000
REQUEST_TIMEOUT = 60

WAZUH_SSL_VERIFY = os.getenv("WAZUH_SSL_VERIFY", "False").lower() in ("true", "1", "yes")
WAZUH_CA_PATH = os.getenv("WAZUH_CA_PATH", "")

if WAZUH_SSL_VERIFY:
    verify_param = WAZUH_CA_PATH if WAZUH_CA_PATH else True
else:
    verify_param = False

VULN_SOURCE_FIELDS = [
    "agent.id", "agent.name",
    "host.os.full", "host.os.platform", "host.os.version",
    "package.name", "package.version", "package.type", "package.architecture",
    "vulnerability.id", "vulnerability.severity",
    "vulnerability.score.base", "vulnerability.score.version",
    "vulnerability.detected_at", "vulnerability.published_at",
    "vulnerability.description", "vulnerability.reference",
    "vulnerability.scanner.vendor",
]

# Errores que justifican reintento: red caida, timeout, server 5xx.
# NO se reintenta auth invalida (401), not-found (404) ni payload invalido (400):
# esos son fallos permanentes, reintentar solo desperdicia tiempo.
_RETRYABLE_NETWORK_EXC = (
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
    requests.exceptions.ChunkedEncodingError,
)


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, _RETRYABLE_NETWORK_EXC):
        return True
    if isinstance(exc, requests.exceptions.HTTPError):
        resp = getattr(exc, "response", None)
        if resp is not None and 500 <= resp.status_code < 600:
            return True
    return False


# 3 intentos con backoff exponencial: 1s, 2s, 4s (max 10s).
# `before_sleep_log` emite WARNING antes de cada reintento, asi queda registrado.
with_retry = retry(
    retry=retry_if_exception(_is_retryable),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    before_sleep=before_sleep_log(log, logging.WARNING),
    reraise=True,
)


def _build_session(wazuh_user: str, wazuh_password: str) -> requests.Session:
    session = requests.Session()
    session.auth = HTTPBasicAuth(wazuh_user, wazuh_password)
    session.verify = verify_param
    return session


@with_retry
def _scroll_start(
    session: requests.Session, indexer_url: str
) -> Tuple[Optional[str], List[Dict[str, Any]]]:
    url = f"{indexer_url}/{VULN_INDEX}/_search?scroll={SCROLL_TTL}"
    # sort=_doc es el orden mas eficiente para scroll (no calcula scoring)
    body = {"size": BATCH_SIZE, "_source": VULN_SOURCE_FIELDS, "sort": ["_doc"]}
    resp = session.post(url, json=body, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    return data.get("_scroll_id"), data["hits"]["hits"]


@with_retry
def _scroll_next(
    session: requests.Session, indexer_url: str, scroll_id: str
) -> Tuple[Optional[str], List[Dict[str, Any]]]:
    url = f"{indexer_url}/_search/scroll"
    body = {"scroll": SCROLL_TTL, "scroll_id": scroll_id}
    resp = session.post(url, json=body, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    return data.get("_scroll_id"), data["hits"]["hits"]


def _scroll_clear(
    session: requests.Session, indexer_url: str, scroll_id: str
) -> None:
    # Liberar el cursor en el server. Best-effort: si falla, el scroll expira solo por TTL.
    try:
        session.delete(
            f"{indexer_url}/_search/scroll",
            json={"scroll_id": scroll_id},
            timeout=10,
        )
    except Exception:
        pass


@with_retry
def _count_vulns(session: requests.Session, indexer_url: str) -> int:
    resp = session.get(f"{indexer_url}/{VULN_INDEX}/_count", timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    return int(resp.json().get("count", 0))


def _safe_count(session: requests.Session, indexer_url: str) -> int:
    """Total de vulns (para calcular cada cuanto loguear el progreso). Si falla -> 0 = log por batch."""
    try:
        return _count_vulns(session, indexer_url)
    except Exception:
        return 0


def _progress_step(grand_total: int) -> int:
    """Cada cuantos docs loguear el progreso: apunta a ~20 lineas SIN IMPORTAR el tamano
    (grand_total/20), pero nunca mas fino que un batch. Total desconocido (0) -> por batch."""
    if grand_total <= 0:
        return BATCH_SIZE
    return max(BATCH_SIZE, grand_total // 20)


def _log_scroll_progress(batch_number: int, total: int, grand_total: int, last_logged: int, step: int) -> int:
    """Loguea 'wazuh_scroll_batch' si toca: el primer batch (feedback temprano) o cada `step` docs
    desde el ultimo log. Asi el progreso escala (~20 lineas a cualquier tamano, no ~400 a 4M).
    Devuelve el nuevo `last_logged`."""
    if batch_number == 1 or total - last_logged >= step:
        log.info(
            "wazuh_scroll_batch",
            extra={"batch_number": batch_number, "running_total": total, "total": grand_total},
        )
        return total
    return last_logged


@with_retry
def _scroll_start_sliced(
    session: requests.Session, indexer_url: str, slice_id: int, slice_max: int
) -> Tuple[Optional[str], List[Dict[str, Any]]]:
    
    url = f"{indexer_url}/{VULN_INDEX}/_search?scroll={SCROLL_TTL}"
    body: Dict[str, Any] = {"size": BATCH_SIZE, "_source": VULN_SOURCE_FIELDS, "sort": ["_doc"]}
    if slice_max >= 2:
        body["slice"] = {"id": slice_id, "max": slice_max}
    resp = session.post(url, json=body, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    return data.get("_scroll_id"), data["hits"]["hits"]


def _get_scroll_slices() -> int:
    """Cantidad de slices para el scroll paralelo. Default 1 = scroll secuencial de siempre.
    Se configura por env SYNC_SCROLL_SLICES (ideal ~= nro de shards del indice de Wazuh)."""
    try:
        return max(1, int(os.getenv("SYNC_SCROLL_SLICES", "1")))
    except (TypeError, ValueError):
        return 1


def _put_blocking(q: "_queue.Queue", item: Any, stop: threading.Event) -> None:
    """put en la cola que puede abortar si `stop` se activa: evita que un worker se cuelgue en
    q.put (cola llena) cuando el consumidor abandono (p.ej. por un error de BD)."""
    while not stop.is_set():
        try:
            q.put(item, timeout=0.5)
            return
        except _queue.Full:
            continue



_SLICE_DONE = object()


class _ScrollChannel:
    """Canal compartido entre los workers de slice y el consumidor: cola acotada de batches, senal
    de parada y lista de errores. Agrupa el estado para no pasar tantos argumentos a cada worker."""

    def __init__(self, maxsize: int):
        self.q: "_queue.Queue" = _queue.Queue(maxsize=maxsize)
        self.stop = threading.Event()
        self.errors: List[BaseException] = []


def _slice_worker(channel, indexer_url, wazuh_user, wazuh_password, slice_id, slice_max):
    """Trae UNA slice del scroll y empuja sus batches al canal. Cualquier error se guarda para que
    el generador lo re-lance; al terminar (ok o error) pone el centinela _SLICE_DONE en la cola."""
    session = _build_session(wazuh_user, wazuh_password)
    scroll_id = None
    try:
        scroll_id, hits = _scroll_start_sliced(session, indexer_url, slice_id, slice_max)
        while hits and not channel.stop.is_set():
            _put_blocking(channel.q, [h["_source"] for h in hits], channel.stop)
            if channel.stop.is_set() or not scroll_id:
                break
            scroll_id, hits = _scroll_next(session, indexer_url, scroll_id)
    except Exception as exc:  
        channel.errors.append(exc)
    finally:
        if scroll_id:
            _scroll_clear(session, indexer_url, scroll_id)
        _put_blocking(channel.q, _SLICE_DONE, channel.stop)


def _drain_and_join(channel: "_ScrollChannel", threads) -> None:
    """Cierre seguro: avisa stop y drena la cola hasta que los workers mueran, para desbloquear los
    q.put pendientes si el consumidor abandono (p.ej. error de BD). Evita cuelgues en el join."""
    channel.stop.set()
    while any(t.is_alive() for t in threads):
        try:
            while True:
                channel.q.get_nowait()
        except _queue.Empty:
            pass
        for t in threads:
            t.join(timeout=0.1)


def _iter_vulns_batches_parallel(
    indexer_url: str, wazuh_user: str, wazuh_password: str, slices: int
) -> Generator[List[Dict[str, Any]], None, None]:
    """Scroll PARALELO con sliced scroll de OpenSearch. Lanza `slices` workers (_slice_worker); cada
    uno trae su slice (subconjunto disjunto de docs) y empuja batches a una cola ACOTADA. Este
    generador -consumidor unico- los cede en el orden en que llegan. Beneficios: (1) el fetch de red
    -el cuello del sync- se paraleliza K veces; (2) prefetch gratis: los workers van adelantados
    mientras la BD procesa el batch anterior. La cola acotada da backpressure (no explota memoria).
    Correctitud: la union de las slices = el dataset completo sin duplicados (garantia de OpenSearch);
    el consumidor procesa cada batch igual que el path secuencial (mismo TRUNCATE+insert+upsert)."""
    channel = _ScrollChannel(maxsize=slices * 2)
    grand_total = _safe_count(_build_session(wazuh_user, wazuh_password), indexer_url)
    step = _progress_step(grand_total)
    threads = [
        threading.Thread(
            target=_slice_worker,
            args=(channel, indexer_url, wazuh_user, wazuh_password, i, slices),
            daemon=True,
            name=f"wazuh-slice-{i}",
        )
        for i in range(slices)
    ]
    for t in threads:
        t.start()
    log.info(
        "wazuh_scroll_parallel_started",
        extra={"indexer_url": indexer_url, "slices": slices, "batch_size": BATCH_SIZE, "total": grand_total},
    )

    total = 0
    batch_number = 0
    finished = 0
    last_logged = 0
    try:
        while finished < slices:
            item = channel.q.get()
            if item is _SLICE_DONE:
                finished += 1
                continue
            batch_number += 1
            total += len(item)
            last_logged = _log_scroll_progress(batch_number, total, grand_total, last_logged, step)
            yield item
    finally:
        _drain_and_join(channel, threads)
        log.info(
            "wazuh_scroll_parallel_finished",
            extra={"batches": batch_number, "total_hits": total, "slices": slices},
        )

    if channel.errors:
        raise channel.errors[0]  


def iter_vulns_batches(
    indexer_url: str, wazuh_user: str, wazuh_password: str
) -> Generator[List[Dict[str, Any]], None, None]:
    """
    Itera vulnerabilidades de Wazuh usando Scroll API (OpenSearch).
    Yield: lista de _source por batch (max BATCH_SIZE elementos).
    Permite procesar datasets >10k sin cargar todo en memoria.
    Reintenta automaticamente errores transitorios de red o 5xx del server.
    Con SYNC_SCROLL_SLICES>=2 usa scroll PARALELO (sliced); default 1 = secuencial.
    """
    slices = _get_scroll_slices()
    if slices >= 2:
        yield from _iter_vulns_batches_parallel(indexer_url, wazuh_user, wazuh_password, slices)
        return

    session = _build_session(wazuh_user, wazuh_password)
    grand_total = _safe_count(session, indexer_url)
    step = _progress_step(grand_total)
    log.info("wazuh_scroll_started", extra={"indexer_url": indexer_url, "batch_size": BATCH_SIZE, "total": grand_total})
    scroll_id, hits = _scroll_start(session, indexer_url)
    batch_number = 0
    total = 0
    last_logged = 0
    try:
        while hits:
            batch_number += 1
            total += len(hits)
            last_logged = _log_scroll_progress(batch_number, total, grand_total, last_logged, step)
            yield [h["_source"] for h in hits]
            if not scroll_id:
                break
            scroll_id, hits = _scroll_next(session, indexer_url, scroll_id)
    except Exception:
        log.exception("wazuh_scroll_failed", extra={"indexer_url": indexer_url, "batch_number": batch_number})
        raise
    finally:
        if scroll_id:
            _scroll_clear(session, indexer_url, scroll_id)
        log.info(
            "wazuh_scroll_finished",
            extra={"batches": batch_number, "total_hits": total},
        )


def fetch_all_vulns(
    indexer_url: str, wazuh_user: str, wazuh_password: str
) -> List[Dict[str, Any]]:
    """
    Retorna TODAS las vulnerabilidades acumuladas en una lista.
    Mantiene compatibilidad con el codigo existente.
    Para datasets grandes (>10k) prefiere iter_vulns_batches().
    """
    all_vulns: List[Dict[str, Any]] = []
    for batch in iter_vulns_batches(indexer_url, wazuh_user, wazuh_password):
        all_vulns.extend(batch)
    return all_vulns


@with_retry
def _test_connection_request(indexer_url: str, wazuh_user: str, wazuh_password: str) -> int:
    resp = requests.get(
        indexer_url,
        auth=HTTPBasicAuth(wazuh_user, wazuh_password),
        verify=verify_param,
        timeout=10,
    )
    # 5xx triggerea retry via raise_for_status; 4xx no, son configuracion.
    if 500 <= resp.status_code < 600:
        resp.raise_for_status()
    return resp.status_code


def test_connection(indexer_url: str, wazuh_user: str, wazuh_password: str) -> bool:
    try:
        return _test_connection_request(indexer_url, wazuh_user, wazuh_password) == 200
    except Exception:
        return False
