# app/wazuh_client.py
import logging
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
    session.verify = False
    return session


@with_retry
def _scroll_start(
    session: requests.Session, indexer_url: str
) -> Tuple[Optional[str], List[Dict[str, Any]]]:
    url = f"{indexer_url}/{VULN_INDEX}/_search?scroll={SCROLL_TTL}"
    # sort=_doc es el orden mas eficiente para scroll (no calcula scoring)
    body = {"size": BATCH_SIZE, "_source": True, "sort": ["_doc"]}
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


def iter_vulns_batches(
    indexer_url: str, wazuh_user: str, wazuh_password: str
) -> Generator[List[Dict[str, Any]], None, None]:
    """
    Itera vulnerabilidades de Wazuh usando Scroll API (OpenSearch).
    Yield: lista de _source por batch (max BATCH_SIZE elementos).
    Permite procesar datasets >10k sin cargar todo en memoria.
    Reintenta automaticamente errores transitorios de red o 5xx del server.
    """
    session = _build_session(wazuh_user, wazuh_password)
    log.info("wazuh_scroll_started", extra={"indexer_url": indexer_url, "batch_size": BATCH_SIZE})
    scroll_id, hits = _scroll_start(session, indexer_url)
    batch_number = 0
    total = 0
    try:
        while hits:
            batch_number += 1
            total += len(hits)
            log.info(
                "wazuh_scroll_batch",
                extra={"batch_number": batch_number, "batch_size": len(hits), "running_total": total},
            )
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
        verify=False,
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
