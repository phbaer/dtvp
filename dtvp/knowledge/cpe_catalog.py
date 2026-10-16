"""Instance-local immutable NVD catalog captures with disposable SQLite search indexes."""

import base64
import fcntl
import gzip
import hashlib
import io
import os
import re
import sqlite3
import tarfile
import tempfile
import zlib
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path, PurePosixPath

import httpx
import ijson
from ijson.common import ObjectBuilder

from dtvp.knowledge.cpe import validate_cpe
from dtvp.knowledge.legacy_archive import strict_json
from dtvp.storage import Artifacts, canonical, digest

FORMAT = "dtvp.cpe-catalog-generation/1"
INDEX_FORMAT = "dtvp.cpe-catalog-index/1"
META_URL = "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.meta"
ARCHIVE_URL = "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz"
CHUNK_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_DECODED_BYTES = 8 * 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 512 * 1024 * 1024
MAX_RECORD_BYTES = 1024 * 1024
MAX_RECORDS = 10_000_000
MAX_MEMBERS = 1000
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_UNEMITTED_BYTES = 16 * 1024 * 1024
_UNSPECIFIED = object()
LIMITATIONS = [
    "META hashes establish consistency of captured archive bytes, not publisher authenticity or completeness of NVD's knowledge.",
    "Search uses a disposable generation-bound local projection; original archive chunks remain authoritative source evidence.",
    "Candidates do not establish component identity, vulnerability applicability or human approval; project mapping adoption remains explicit.",
    "No product state, reviewed mapping, supplied dictionary or approval is changed by catalog capture or search.",
]


def _sha(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        raise ValueError("Invalid catalog generation digest")
    return value


def parse_meta(raw):
    if not raw or len(raw) > 64 * 1024:
        raise ValueError("Catalog META exceeds supported byte bounds")
    try:
        # Current NVD META also uses literal escaped CRLF separators.
        text = raw.decode("utf-8").replace("\\r\\n", "\n")
    except UnicodeError as error:
        raise ValueError("Catalog META must be UTF-8") from error
    values = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        key, separator, value = line.partition(":")
        if not separator or not key or key in values:
            raise ValueError("Malformed or duplicate catalog META fields")
        values[key] = value.strip()
    for key in ("size", "gzSize"):
        value = values.get(key, "")
        if not re.fullmatch(r"[0-9]{1,12}", value):
            raise ValueError("Catalog META requires exact size and gzSize")
        values[key] = int(value)
    if not 0 < values["size"] <= MAX_DECODED_BYTES or not 0 < values["gzSize"] <= MAX_ARCHIVE_BYTES:
        raise ValueError("Catalog META exceeds supported archive limits")
    values["sha256"] = _sha(values.get("sha256", "").lower())
    if not isinstance(values.get("lastModifiedDate"), str) or len(values["lastModifiedDate"]) > 100:
        raise ValueError("Catalog META requires a bounded modification declaration")
    if "dtvpSynthetic" in values and values["dtvpSynthetic"] != "true":
        raise ValueError("Unsupported synthetic catalog marker")
    return values


class _Measured:
    def __init__(self, source, maximum, *, event_window=False):
        self.source, self.maximum = source, maximum
        self.event_window, self.unemitted = event_window, 0
        self.size, self.hasher = 0, hashlib.sha256()
        self.tail = b""

    def read(self, size=-1):
        raw = self.source.read(size)
        self.size += len(raw)
        self.unemitted += len(raw)
        if self.event_window and self.unemitted > MAX_UNEMITTED_BYTES:
            raise ValueError("Catalog JSON parser made no progress within byte window")
        if self.size > self.maximum:
            raise ValueError("Catalog decoded byte limit exceeded")
        self.hasher.update(raw)
        self.tail = (self.tail + raw)[-65536:]
        return raw

    def readinto(self, target):
        raw = self.read(len(target))
        target[: len(raw)] = raw
        return len(raw)


def _row(db, product, ordinal, member):
    if not isinstance(product, dict) or not isinstance(product.get("cpe"), dict):
        raise ValueError("Catalog products require explicit CPE objects")
    cpe = product["cpe"]
    name, identity = cpe.get("cpeName"), cpe.get("cpeNameId")
    validate_cpe(name)
    if (
        not isinstance(identity, str)
        or not identity.strip()
        or len(identity) > 200
        or type(cpe.get("deprecated")) is not bool
    ):
        raise ValueError("Catalog CPE records require IDs and explicit deprecated flags")
    titles = cpe.get("titles", [])
    if (
        not isinstance(titles, list)
        or len(titles) > 100
        or any(
            not isinstance(item, dict)
            or not isinstance(item.get("title"), str)
            or len(item["title"]) > 10_000
            for item in titles
        )
    ):
        raise ValueError("Malformed or excessive catalog titles")
    raw = canonical(product)
    if len(raw) > MAX_RECORD_BYTES:
        raise ValueError("Catalog record exceeds supported byte bounds")
    sha = digest(raw)
    try:
        db.execute(
            "INSERT INTO entries VALUES (?,?,?,?,?,?,?)",
            (ordinal, name, identity, int(cpe["deprecated"]), raw.decode(), sha, member),
        )
        db.execute(
            "INSERT INTO search(rowid,terms) VALUES (?,?)",
            (ordinal, " ".join([name, identity, *[item["title"] for item in titles]])),
        )
    except sqlite3.IntegrityError as error:
        raise ValueError("Duplicate CPE names or IDs in catalog") from error
    return sha


def _member(db, source, name, ordinal):
    stream = _Measured(source, MAX_MEMBER_BYTES, event_window=True)
    stack, headers, ignored = [], {}, set()
    builder, record_size, count, products = None, 0, 0, False
    retained_key_bytes, header_bytes = 0, 0
    try:
        for prefix, event, value in ijson.parse(stream, use_float=True):
            stream.unemitted = 0
            if event == "map_key":
                if len(value) > 1024 or len(stack[-1][1]) >= 10_000:
                    raise ValueError("Catalog JSON object key bounds exceeded")
                key_bytes = len(value.encode()) + 64
                retained_key_bytes += key_bytes
                stack[-1][2] += key_bytes
                if retained_key_bytes > 8 * 1024 * 1024:
                    raise ValueError("Catalog JSON object key memory bound exceeded")
                if value in stack[-1][1]:
                    raise ValueError("Duplicate catalog JSON keys")
                stack[-1][1].add(value)
            elif event in {"start_map", "start_array"}:
                if not stack and (prefix or event != "start_map"):
                    raise ValueError("Catalog chunk root must be an object")
                stack.append([event, set(), 0])
                if len(stack) > 64:
                    raise ValueError("Catalog JSON nesting exceeds supported depth")
            if isinstance(value, str) and len(value) > MAX_RECORD_BYTES:
                raise ValueError("Catalog JSON token exceeds supported size")
            if prefix == "products" and event == "start_array" and len(stack) == 2:
                products = True
            if (
                prefix == "products.item"
                and event == "start_map"
                and len(stack) == 3
                and stack[-2][0] == "start_array"
            ):
                # ijson prefixes are strings: a literal top-level key named
                # "products.item" must never impersonate an array occurrence.
                builder, record_size = ObjectBuilder(), 0
            elif prefix == "products.item" and builder is None:
                raise ValueError("Catalog products must contain objects")
            if builder is not None:
                record_size += len(value.encode()) if isinstance(value, str) else 16
                if record_size > MAX_RECORD_BYTES:
                    raise ValueError("Catalog record exceeds supported byte bounds")
                builder.event(event, value)
                if prefix == "products.item" and event == "end_map":
                    count += 1
                    if ordinal + count > MAX_RECORDS:
                        raise ValueError("Catalog record limit exceeded")
                    _row(db, builder.value, ordinal + count, name)
                    builder = None
            elif prefix and "." not in prefix and prefix != "products":
                if event in {"string", "number", "boolean", "null"}:
                    header_bytes += len(canonical({prefix: value}))
                    if header_bytes > 64 * 1024:
                        raise ValueError("Catalog chunk header byte limit exceeded")
                    headers[prefix] = value
                elif event in {"start_map", "start_array"}:
                    ignored.add(prefix)
            if event in {"end_map", "end_array"}:
                retained_key_bytes -= stack.pop()[2]
    except ijson.JSONError as error:
        raise ValueError("Malformed catalog JSON") from error
    if not products or builder is not None or stack:
        raise ValueError("Incomplete catalog chunk")
    if headers.get("format") != "NVD_CPE" or headers.get("version") != "2.0":
        raise ValueError("Only NVD CPE 2.0 JSON chunks are supported")
    for key in ("startIndex", "totalResults", "resultsPerPage"):
        if type(headers.get(key)) is not int or not 0 <= headers[key] <= MAX_RECORDS:
            raise ValueError("Catalog chunk requires bounded integral pagination fields")
    if count != headers["resultsPerPage"]:
        raise ValueError("Catalog chunk count differs from its declaration")
    return {
        "name": name,
        "sha256": stream.hasher.hexdigest(),
        "size": stream.size,
        "records": count,
        "header": headers,
        "unprojected_header_fields": sorted(ignored),
    }


def _schema(db):
    db.executescript("""
    PRAGMA journal_mode=OFF;
    PRAGMA synchronous=OFF;
    CREATE TABLE meta (generation TEXT NOT NULL, format TEXT NOT NULL);
    CREATE TABLE entries (ordinal INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, identity TEXT NOT NULL UNIQUE, deprecated INTEGER NOT NULL, record TEXT NOT NULL, sha TEXT NOT NULL, member TEXT NOT NULL);
    CREATE VIRTUAL TABLE search USING fts5(terms);
    """)


def _index(archive, meta, target):
    members, seen, count, base, total = [], set(), 0, None, None
    report_bytes = 0
    with sqlite3.connect(target) as db, gzip.open(archive, "rb") as decoded:
        _schema(db)
        measured = _Measured(decoded, MAX_DECODED_BYTES)
        try:
            with tarfile.open(fileobj=measured, mode="r|") as tar:
                for item in tar:
                    path = PurePosixPath(item.name)
                    if (
                        path.is_absolute()
                        or ".." in path.parts
                        or "\\" in item.name
                        or len(item.name) > 500
                    ):
                        raise ValueError("Unsafe catalog archive member path")
                    if item.isdir():
                        continue
                    if (
                        not item.isfile()
                        or not item.name.endswith(".json")
                        or item.name in seen
                        or item.size > MAX_MEMBER_BYTES
                    ):
                        raise ValueError("Unsupported or duplicate catalog archive member")
                    seen.add(item.name)
                    if len(seen) > MAX_MEMBERS:
                        raise ValueError("Catalog archive member limit exceeded")
                    report = _member(db, tar.extractfile(item), item.name, count)
                    if report["size"] != item.size:
                        raise ValueError("Catalog archive member size differs")
                    header = report["header"]
                    if header.get("dtvpSynthetic", False) is not (
                        meta.get("dtvpSynthetic") == "true"
                    ):
                        raise ValueError("Catalog synthetic source markers disagree")
                    if base is None:
                        base, total = header["startIndex"], header["totalResults"]
                        if base not in {0, 1}:
                            raise ValueError("Catalog must start at the first result")
                    if header["startIndex"] != base + count or header["totalResults"] != total:
                        raise ValueError("Catalog chunk coverage has gaps or conflicting totals")
                    count += report["records"]
                    report_bytes += len(canonical(report))
                    if report_bytes > MAX_MANIFEST_BYTES - 64 * 1024:
                        raise ValueError("Catalog aggregate manifest byte limit exceeded")
                    members.append(report)
                padding = measured.size - tar.offset
                if (
                    padding < 0
                    or padding > len(measured.tail)
                    or (padding and any(measured.tail[-padding:]))
                ):
                    raise ValueError("Unexpected bytes after catalog archive members")
            while block := measured.read(1024 * 1024):
                if any(block):
                    raise ValueError("Unexpected bytes after catalog archive members")
        except (tarfile.TarError, gzip.BadGzipFile, EOFError, zlib.error) as error:
            raise ValueError("Malformed or truncated catalog archive") from error
        if not members or count != total or count > MAX_RECORDS:
            raise ValueError("Catalog chunks do not cover the complete declared result set")
        if measured.size != meta["size"] or measured.hasher.hexdigest() != meta["sha256"]:
            raise ValueError("Catalog archive differs from decoded META size/hash")
    return {"records": count, "index_base": base, "members": members}


def _signature(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


@lru_cache(maxsize=8)
def _verified_index(path, expected_sha, expected_size, signature):
    # Rehash each exact filesystem identity. Metadata changes force fresh proof.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        if _signature(os.fstat(source.fileno())) != signature or signature[2] != expected_size:
            raise ValueError("Catalog index changed; rebuild it")
        hasher = hashlib.sha256()
        while raw := source.read(1024 * 1024):
            hasher.update(raw)
        if hasher.hexdigest() != expected_sha or _signature(os.fstat(source.fileno())) != signature:
            raise ValueError("Catalog index bytes differ from its verified rebuild receipt")
    return True


class Catalog:
    def __init__(self, root):
        self.root = Path(root).resolve()

    @contextmanager
    def _lock(self):
        self.root.mkdir(parents=True, exist_ok=True)
        with (self.root / ".catalog.lock").open("a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    def current(self):
        try:
            return _sha((self.root / "CURRENT").read_text().strip())
        except FileNotFoundError:
            return None

    def manifest(self, generation=None):
        generation = _sha(generation or self.current())
        if not (self.root / "objects").is_dir():
            raise ValueError("Catalog storage is unavailable")
        raw = Artifacts(self.root / "objects").read(generation)
        if len(raw) > MAX_MANIFEST_BYTES:
            raise ValueError("Catalog manifest exceeds byte bounds")
        value = strict_json(raw)
        if not isinstance(value, dict) or value.get("format") != FORMAT:
            raise ValueError("Unsupported catalog manifest")
        return generation, value

    def _atomic(self, path, raw):
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _install_index(self, temporary, generation):
        with sqlite3.connect(temporary) as db:
            db.execute("INSERT INTO meta VALUES (?,?)", (generation, INDEX_FORMAT))
        with Path(temporary).open("rb") as stream:
            os.fsync(stream.fileno())
        target = self.root / "indexes" / (generation + ".sqlite")
        target.parent.mkdir(parents=True, exist_ok=True)
        index_size, index_hasher = Path(temporary).stat().st_size, hashlib.sha256()
        with Path(temporary).open("rb") as source:
            while raw := source.read(1024 * 1024):
                index_hasher.update(raw)
        receipt = {
            "format": INDEX_FORMAT,
            "generation": generation,
            "index_sha256": index_hasher.hexdigest(),
            "index_size": index_size,
        }
        receipt_sha = Artifacts(self.root / "objects").put(canonical(receipt))
        os.replace(temporary, target)
        self._atomic(target.with_suffix(".receipt"), (receipt_sha + "\n").encode())
        directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def import_archive(self, archive, metadata, *, expected=_UNSPECIFIED):
        with Path(metadata).open("rb") as source:
            raw_meta = source.read(64 * 1024 + 1)
        meta = parse_meta(raw_meta)
        with self._lock(), tempfile.TemporaryDirectory(dir=self.root) as staging:
            if expected is not _UNSPECIFIED and self.current() != expected:
                raise ValueError("Catalog selection changed during acquisition")
            objects, chunks, hasher, size = (
                Artifacts(self.root / "objects"),
                [],
                hashlib.sha256(),
                0,
            )
            local = Path(staging) / "archive.tar.gz"
            with Path(archive).open("rb") as source, local.open("wb") as target:
                while raw := source.read(CHUNK_BYTES):
                    size += len(raw)
                    if size > MAX_ARCHIVE_BYTES:
                        raise ValueError("Catalog compressed byte limit exceeded")
                    hasher.update(raw)
                    target.write(raw)
                    chunks.append({"sha256": objects.put(raw), "size": len(raw)})
            if size != meta["gzSize"]:
                raise ValueError("Catalog compressed size differs from META")
            index = Path(staging) / "index.sqlite"
            report = _index(local, meta, index)
            synthetic = meta.get("dtvpSynthetic") == "true"
            manifest = {
                "format": FORMAT,
                "assurance": "synthetic_META_consistent_complete_archive"
                if synthetic
                else "META_consistent_complete_archive",
                "synthetic": synthetic,
                "source": "Synthetic NVD-shaped CPE demonstration"
                if synthetic
                else "NVD CPE Dictionary 2.0 (claimed)",
                "meta_sha256": objects.put(raw_meta),
                "meta": meta,
                "archive_sha256": hasher.hexdigest(),
                "archive_size": size,
                "chunks": chunks,
                **report,
                "limitations": LIMITATIONS,
            }
            manifest_raw = canonical(manifest)
            if len(manifest_raw) > MAX_MANIFEST_BYTES:
                raise ValueError("Catalog manifest exceeds byte bounds")
            generation = objects.put(manifest_raw)
            self._install_index(index, generation)
            self._atomic(self.root / "CURRENT", (generation + "\n").encode())
            return {"generation": generation, **manifest}

    def verify(self, generation=None, *, rebuild=False):
        with self._lock(), tempfile.TemporaryDirectory(dir=self.root) as staging:
            generation, manifest = self.manifest(generation)
            objects = Artifacts(self.root / "objects")
            meta = parse_meta(objects.read(manifest["meta_sha256"]))
            if meta != manifest["meta"]:
                raise ValueError("Catalog META manifest differs")
            local, hasher, size = Path(staging) / "archive.tar.gz", hashlib.sha256(), 0
            chunks = manifest.get("chunks")
            if (
                not isinstance(chunks, list)
                or not 1 <= len(chunks) <= MAX_ARCHIVE_BYTES // CHUNK_BYTES + 1
            ):
                raise ValueError("Catalog raw chunk manifest exceeds bounds")
            with local.open("wb") as target:
                for chunk in chunks:
                    raw = objects.read(chunk["sha256"])
                    size += len(raw)
                    if (
                        len(raw) != chunk["size"]
                        or len(raw) > CHUNK_BYTES
                        or size > MAX_ARCHIVE_BYTES
                    ):
                        raise ValueError("Catalog raw chunk size differs")
                    target.write(raw)
                    hasher.update(raw)
            if (
                size != manifest["archive_size"]
                or size != meta["gzSize"]
                or hasher.hexdigest() != manifest["archive_sha256"]
            ):
                raise ValueError("Catalog raw archive manifest differs")
            index = Path(staging) / "index.sqlite"
            report = _index(local, meta, index)
            if any(report[key] != manifest[key] for key in report):
                raise ValueError("Catalog normalized coverage manifest differs")
            if rebuild:
                self._install_index(index, generation)
            return {
                "generation": generation,
                "verified": True,
                "index_rebuilt": rebuild,
                "records": report["records"],
                "limitations": LIMITATIONS,
            }

    def _verify_index(self, generation):
        target = self.root / "indexes" / (generation + ".sqlite")
        try:
            receipt_sha = _sha(target.with_suffix(".receipt").read_text().strip())
            receipt = strict_json(Artifacts(self.root / "objects").read(receipt_sha))
            if (
                not isinstance(receipt, dict)
                or receipt.get("generation") != generation
                or receipt.get("format") != INDEX_FORMAT
                or type(receipt.get("index_size")) is not int
                or not 0 < receipt["index_size"] <= 4 * MAX_DECODED_BYTES
            ):
                raise ValueError("Invalid catalog index receipt; rebuild it")
            signature = _signature(target.stat(follow_symlinks=False))
            _verified_index(
                str(target), _sha(receipt.get("index_sha256")), receipt["index_size"], signature
            )
            return target, signature
        except OSError as error:
            raise ValueError("Catalog index unavailable; rebuild it") from error

    def search(self, query, *, generation=None, offset=0, limit=50, include_deprecated=False):
        if (
            not isinstance(query, str)
            or not 2 <= len(query.strip()) <= 200
            or offset < 0
            or offset > 100_000
            or not 1 <= limit <= 200
        ):
            raise ValueError("Catalog search requires bounded query and pagination")
        generation, manifest = self.manifest(generation)
        target, index_signature = self._verify_index(generation)
        expression = " AND ".join('"' + token.replace('"', '""') + '"' for token in query.split())
        try:
            with sqlite3.connect(target.as_uri() + "?mode=ro", uri=True) as db:
                budget = [0]

                def bounded():
                    budget[0] += 1
                    return int(budget[0] > 20_000)

                db.set_progress_handler(bounded, 1000)
                if db.execute("SELECT generation,format FROM meta").fetchall() != [
                    (generation, INDEX_FORMAT)
                ]:
                    raise ValueError("Catalog index generation differs; rebuild it")
                predicate = "" if include_deprecated else " AND entries.deprecated=0"
                sql = (
                    " FROM search JOIN entries ON entries.ordinal=search.rowid WHERE search MATCH ?"
                    + predicate
                )
                total = db.execute("SELECT count(*)" + sql, (expression,)).fetchone()[0]
                rows = db.execute(
                    "SELECT entries.record,entries.sha,entries.member"
                    + sql
                    + " ORDER BY entries.name LIMIT ? OFFSET ?",
                    (expression, limit, offset),
                ).fetchall()
        except sqlite3.Error as error:
            raise ValueError(
                "Catalog search index unavailable or query budget exceeded; verify/rebuild the index"
            ) from error
        if _signature(target.stat(follow_symlinks=False)) != index_signature:
            raise ValueError("Catalog index changed during query; retry after rebuild")
        items = []
        for raw, sha, member in rows:
            if digest(raw.encode()) != sha:
                raise ValueError("Catalog search record differs; rebuild the index")
            items.append(
                {"record": strict_json(raw.encode()), "record_sha256": sha, "member": member}
            )
        result = {
            "generation": generation,
            "archive_sha256": manifest["archive_sha256"],
            "meta_sha256": manifest["meta_sha256"],
            "query": query,
            "source": manifest["source"],
            "synthetic": manifest.get("synthetic", False),
            "total": total,
            "items": items,
            "next_offset": offset + limit if offset + limit < total else None,
            "limitations": LIMITATIONS,
        }
        if len(canonical(result)) > 8 * 1024 * 1024:
            raise ValueError("Catalog search output exceeds byte limit; reduce page size")
        return result

    def export(self, query, **scope):
        """Produce a bounded candidate file for existing explicit curated intake."""
        from dtvp.knowledge.cpe_sources import dictionary

        page = self.search(query, **scope)
        records, projected = [], set()
        for item in page["items"]:
            cpe = item["record"]["cpe"]
            projected.update(set(cpe) - {"cpeName", "cpeNameId", "deprecated", "refs"})
            records.append(
                {
                    "cpeName": cpe["cpeName"],
                    "cpeNameId": cpe["cpeNameId"],
                    "deprecated": cpe["deprecated"],
                    "refs": cpe.get("refs", []),
                    "source": ("synthetic-catalog:" if page.get("synthetic") else "nvd-catalog:")
                    + page["generation"],
                    "publisher": "Synthetic demonstration"
                    if page.get("synthetic")
                    else "NVD (claimed)",
                }
            )
        content = canonical(records)
        # Reuse the exact established bounded destination contract, no silent cuts.
        if len(content) > 2 * 1024 * 1024:
            raise ValueError("Curated catalog export exceeds 2 MiB; reduce page size")
        dictionary(content, "nvd-catalog:" + page["generation"])
        return {
            "dictionary": records,
            "content_base64": base64.b64encode(content).decode(),
            "artifact_sha256": digest(content),
            "capture": page,
            "unprojected_record_fields": sorted(projected),
            "selection_scope": "This explicit page only; later pages are not exported or automatically selected.",
        }

    def mirror(self, *, http=None):
        """Explicit fixed-origin acquisition; no polling or implicit startup download."""

        def acquire(client):
            expected = self.current()

            def meta_bytes():
                with client.stream(
                    "GET", META_URL, follow_redirects=False, headers={"Accept-Encoding": "identity"}
                ) as response:
                    response.raise_for_status()
                    raw = bytearray()
                    for block in response.iter_bytes():
                        raw.extend(block)
                        if len(raw) > 64 * 1024:
                            raise ValueError("Catalog META byte limit exceeded")
                parse_meta(raw)
                return bytes(raw)

            before = meta_bytes()
            if expected and self.manifest(expected)[1]["meta_sha256"] == digest(before):
                return {"generation": expected, "changed": False, "limitations": LIMITATIONS}
            # Download staging is external to persistent catalog; failed collection
            # neither creates a generation nor changes its active selection.
            with tempfile.TemporaryDirectory(prefix="dtvp-cpe-acquisition-") as staging:
                archive, meta = Path(staging) / "source.tar.gz", Path(staging) / "source.meta"
                size = 0
                with (
                    client.stream(
                        "GET",
                        ARCHIVE_URL,
                        follow_redirects=False,
                        headers={"Accept-Encoding": "identity"},
                    ) as response,
                    archive.open("wb") as target,
                ):
                    response.raise_for_status()
                    if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                        raise ValueError("Unexpected catalog HTTP content encoding")
                    for raw in response.iter_bytes():
                        size += len(raw)
                        if size > MAX_ARCHIVE_BYTES:
                            raise ValueError("Catalog compressed byte limit exceeded")
                        target.write(raw)
                if before != meta_bytes():
                    raise ValueError(
                        "Catalog META changed during download; retry acquisition explicitly"
                    )
                meta.write_bytes(before)
                return {"changed": True, **self.import_archive(archive, meta, expected=expected)}

        if http is not None:
            return acquire(http)
        with httpx.Client(timeout=60, follow_redirects=False) as client:
            return acquire(client)


def demo_catalog(root):
    """Populate only an unselected catalog with explicit invented offline evidence."""
    catalog = Catalog(root)
    if catalog.current() is not None:
        raise ValueError("Demo requires an empty catalog selection; use a new demo root")
    with tempfile.TemporaryDirectory(prefix="dtvp-cpe-demo-") as staging:
        products = [
            {
                "cpe": {
                    "cpeName": f"cpe:2.3:a:example:demo_library:{version}:*:*:*:*:*:*:*",
                    "cpeNameId": f"synthetic-demo-library-{index}",
                    "deprecated": index == 0,
                    "titles": [{"title": f"Synthetic demo library {version}", "lang": "en"}],
                    "refs": [{"ref": "https://example.invalid/synthetic-catalog"}],
                    "dtvpSynthetic": True,
                }
            }
            for index, version in enumerate(["1.0.0", "2.0.0", "3.0.0"])
        ]
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for index, values in enumerate([products[:2], products[2:]]):
                content = canonical(
                    {
                        "format": "NVD_CPE",
                        "version": "2.0",
                        "dtvpSynthetic": True,
                        "startIndex": 1 + index * 2,
                        "totalResults": 3,
                        "resultsPerPage": len(values),
                        "products": values,
                    }
                )
                info = tarfile.TarInfo(f"synthetic-cpe/chunk-{index}.json")
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
        decoded = raw.getvalue()
        compressed = gzip.compress(decoded, mtime=0)
        archive, meta = Path(staging) / "synthetic.tar.gz", Path(staging) / "synthetic.meta"
        archive.write_bytes(compressed)
        meta.write_text(
            f"lastModifiedDate:2099-01-01T00:00:00Z\nsize:{len(decoded)}\ngzSize:{len(compressed)}\nsha256:{digest(decoded)}\ndtvpSynthetic:true\n"
        )
        return catalog.import_archive(archive, meta, expected=None)
