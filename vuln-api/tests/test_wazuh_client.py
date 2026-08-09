"""Tests unitarios de wazuhClientService: scroll, reintentos y test de conexión.
Sin red: las respuestas HTTP se simulan con fakes."""
import pytest
import requests
import tenacity

from app.services import wazuhClientService as wcs


class FakeResponse:
    def __init__(self, status_code=200, json_data=None):
        self.status_code = status_code
        self._json = json_data or {}

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(
                f"HTTP {self.status_code}", response=self
            )


class FakeSession:
    """Devuelve respuestas en orden por cada .post(); registra los .delete()."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.post_calls = 0
        self.delete_calls = []

    def post(self, url, **kwargs):
        self.post_calls += 1
        return self.responses.pop(0)

    def delete(self, url, **kwargs):
        self.delete_calls.append(url)
        return FakeResponse(200)


def _hit(cve):
    return {"_source": {"vulnerability": {"id": cve}}}


def _no_wait(monkeypatch, fn):
    """Anula el backoff de tenacity para que los tests de reintento sean instantáneos."""
    monkeypatch.setattr(fn.retry, "wait", tenacity.wait_none())


# _is_retryable


def test_is_retryable_network_errors():
    assert wcs._is_retryable(requests.exceptions.ConnectionError()) is True
    assert wcs._is_retryable(requests.exceptions.Timeout()) is True


def test_is_retryable_http_5xx_yes_4xx_no():
    err_500 = requests.exceptions.HTTPError(response=FakeResponse(503))
    err_401 = requests.exceptions.HTTPError(response=FakeResponse(401))
    assert wcs._is_retryable(err_500) is True
    assert wcs._is_retryable(err_401) is False


def test_is_retryable_other_exceptions_no():
    assert wcs._is_retryable(ValueError("x")) is False


# iter_vulns_batches


def test_iter_batches_multiple_batches_and_scroll_clear(monkeypatch):
    session = FakeSession([
        FakeResponse(200, {"_scroll_id": "s1", "hits": {"hits": [_hit("CVE-1"), _hit("CVE-2")]}}),
        FakeResponse(200, {"_scroll_id": "s2", "hits": {"hits": [_hit("CVE-3")]}}),
        FakeResponse(200, {"_scroll_id": "s3", "hits": {"hits": []}}),
    ])
    monkeypatch.setattr(wcs, "_build_session", lambda u, p: session)

    batches = list(wcs.iter_vulns_batches("https://x:9200", "u", "p"))

    assert len(batches) == 2
    assert [v["vulnerability"]["id"] for v in batches[0]] == ["CVE-1", "CVE-2"]
    assert [v["vulnerability"]["id"] for v in batches[1]] == ["CVE-3"]
    # El cursor se libera en el server al terminar
    assert len(session.delete_calls) == 1


def test_iter_batches_stops_without_scroll_id(monkeypatch):
    session = FakeSession([
        FakeResponse(200, {"_scroll_id": None, "hits": {"hits": [_hit("CVE-1")]}}),
    ])
    monkeypatch.setattr(wcs, "_build_session", lambda u, p: session)

    batches = list(wcs.iter_vulns_batches("https://x:9200", "u", "p"))

    assert len(batches) == 1
    # Sin scroll_id no hay cursor que liberar
    assert session.delete_calls == []


def test_iter_batches_error_still_clears_scroll(monkeypatch):
    session = FakeSession([
        FakeResponse(200, {"_scroll_id": "s1", "hits": {"hits": [_hit("CVE-1")]}}),
        FakeResponse(401),  # error permanente a mitad del scroll
    ])
    monkeypatch.setattr(wcs, "_build_session", lambda u, p: session)

    with pytest.raises(requests.exceptions.HTTPError):
        list(wcs.iter_vulns_batches("https://x:9200", "u", "p"))

    # Aun fallando, el finally libera el cursor
    assert len(session.delete_calls) == 1


def test_scroll_start_retries_on_5xx_then_succeeds(monkeypatch):
    _no_wait(monkeypatch, wcs._scroll_start)
    session = FakeSession([
        FakeResponse(502),
        FakeResponse(503),
        FakeResponse(200, {"_scroll_id": "ok", "hits": {"hits": [_hit("CVE-9")]}}),
    ])

    scroll_id, hits = wcs._scroll_start(session, "https://x:9200")

    assert scroll_id == "ok"
    assert len(hits) == 1
    assert session.post_calls == 3  # 2 fallos 5xx + 1 exito


def test_scroll_clear_swallows_errors():
    class BrokenSession:
        def delete(self, *a, **k):
            raise requests.exceptions.ConnectionError()

    # No debe lanzar: liberar el scroll es best-effort
    wcs._scroll_clear(BrokenSession(), "https://x:9200", "s1")


# scroll paralelo (sliced)


def test_parallel_scroll_merges_all_slices(monkeypatch):
    """El scroll paralelo cede la union de TODAS las slices, sin duplicados ni faltantes."""
    def fake_start(session, url, slice_id, slice_max):
        assert slice_max == 3
        return f"sid-{slice_id}", [_hit(f"CVE-{slice_id}-a"), _hit(f"CVE-{slice_id}-b")]

    monkeypatch.setattr(wcs, "_build_session", lambda u, p: object())
    monkeypatch.setattr(wcs, "_scroll_start_sliced", fake_start)
    monkeypatch.setattr(wcs, "_scroll_next", lambda s, u, sid: (None, []))
    monkeypatch.setattr(wcs, "_scroll_clear", lambda *a, **k: None)

    batches = list(wcs._iter_vulns_batches_parallel("https://x:9200", "u", "p", slices=3))

    cves = sorted(v["vulnerability"]["id"] for b in batches for v in b)
    assert cves == ["CVE-0-a", "CVE-0-b", "CVE-1-a", "CVE-1-b", "CVE-2-a", "CVE-2-b"]


def test_parallel_scroll_propagates_worker_error(monkeypatch):
    """Si una slice falla, el error se propaga (sync incompleto no debe pasar silencioso)."""
    def fake_start(session, url, slice_id, slice_max):
        if slice_id == 1:
            raise requests.exceptions.ConnectionError("boom")
        return None, [_hit(f"CVE-{slice_id}")]

    monkeypatch.setattr(wcs, "_build_session", lambda u, p: object())
    monkeypatch.setattr(wcs, "_scroll_start_sliced", fake_start)
    monkeypatch.setattr(wcs, "_scroll_next", lambda s, u, sid: (None, []))
    monkeypatch.setattr(wcs, "_scroll_clear", lambda *a, **k: None)

    with pytest.raises(requests.exceptions.ConnectionError):
        list(wcs._iter_vulns_batches_parallel("https://x:9200", "u", "p", slices=3))


def test_iter_batches_uses_parallel_when_slices_env_set(monkeypatch):
    """iter_vulns_batches delega al scroll paralelo cuando SYNC_SCROLL_SLICES>=2."""
    called = {}

    def fake_parallel(url, u, p, slices):
        called["slices"] = slices
        yield [{"vulnerability": {"id": "CVE-X"}}]

    monkeypatch.setenv("SYNC_SCROLL_SLICES", "4")
    monkeypatch.setattr(wcs, "_iter_vulns_batches_parallel", fake_parallel)

    batches = list(wcs.iter_vulns_batches("https://x:9200", "u", "p"))

    assert called["slices"] == 4
    assert batches == [[{"vulnerability": {"id": "CVE-X"}}]]


def test_iter_batches_sequential_when_slices_unset(monkeypatch):
    """Sin SYNC_SCROLL_SLICES (default 1) usa el path secuencial, no el paralelo."""
    monkeypatch.delenv("SYNC_SCROLL_SLICES", raising=False)

    def _boom(*a, **k):
        raise AssertionError("no deberia usar el path paralelo con slices=1")

    monkeypatch.setattr(wcs, "_iter_vulns_batches_parallel", _boom)
    session = FakeSession([
        FakeResponse(200, {"_scroll_id": None, "hits": {"hits": [_hit("CVE-1")]}}),
    ])
    monkeypatch.setattr(wcs, "_build_session", lambda u, p: session)

    batches = list(wcs.iter_vulns_batches("https://x:9200", "u", "p"))
    assert [v["vulnerability"]["id"] for v in batches[0]] == ["CVE-1"]


class CapSession:
    """Captura el body del ultimo .post() para inspeccionar el request enviado."""
    def __init__(self, response):
        self.response = response
        self.body = None

    def post(self, url, json=None, **kwargs):
        self.body = json
        return self.response


def test_scroll_start_sliced_includes_slice_clause():
    """Con slice_max>=2 el request lleva la clausula slice {id, max} y el _source hoja."""
    sess = CapSession(FakeResponse(200, {"_scroll_id": "s", "hits": {"hits": [_hit("CVE-1")]}}))
    scroll_id, hits = wcs._scroll_start_sliced(sess, "https://x:9200", 1, 4)
    assert scroll_id == "s"
    assert len(hits) == 1
    assert sess.body["slice"] == {"id": 1, "max": 4}
    assert sess.body["_source"] == wcs.VULN_SOURCE_FIELDS
    assert sess.body["sort"] == ["_doc"]


def test_scroll_start_sliced_omits_clause_when_single():
    """Con slice_max<2 NO se agrega la clausula slice (equivale al scroll normal)."""
    sess = CapSession(FakeResponse(200, {"_scroll_id": None, "hits": {"hits": []}}))
    wcs._scroll_start_sliced(sess, "https://x:9200", 0, 1)
    assert "slice" not in sess.body


# fetch_all_vulns


def test_fetch_all_vulns_flattens_batches(monkeypatch):
    monkeypatch.setattr(
        wcs, "iter_vulns_batches",
        lambda *a, **k: iter([[{"a": 1}, {"a": 2}], [{"a": 3}]]),
    )
    result = wcs.fetch_all_vulns("https://x:9200", "u", "p")
    assert result == [{"a": 1}, {"a": 2}, {"a": 3}]


# test_connection


def test_connection_true_on_200(monkeypatch):
    monkeypatch.setattr(wcs.requests, "get", lambda *a, **k: FakeResponse(200))
    assert wcs.test_connection("https://x:9200", "u", "p") is True


def test_connection_false_on_401(monkeypatch):
    monkeypatch.setattr(wcs.requests, "get", lambda *a, **k: FakeResponse(401))
    assert wcs.test_connection("https://x:9200", "u", "p") is False


def test_connection_false_on_network_error(monkeypatch):
    _no_wait(monkeypatch, wcs._test_connection_request)

    def _boom(*a, **k):
        raise requests.exceptions.ConnectionError()

    monkeypatch.setattr(wcs.requests, "get", _boom)
    assert wcs.test_connection("https://x:9200", "u", "p") is False


def test_connection_false_on_5xx_after_retries(monkeypatch):
    _no_wait(monkeypatch, wcs._test_connection_request)
    calls = []

    def _srv_err(*a, **k):
        calls.append(1)
        return FakeResponse(503)

    monkeypatch.setattr(wcs.requests, "get", _srv_err)
    assert wcs.test_connection("https://x:9200", "u", "p") is False
    assert len(calls) == 3  # agoto los 3 intentos
