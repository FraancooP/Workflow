import base64
import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.parse import urlencode, urlsplit


ROOT = Path(os.environ.get("TI1_ROOT", "/opt/recon"))

EVIDENCE = Path(
    os.environ.get("TI1_EVIDENCE", "/home/ti1/evidence")
)


def save(path, value):
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )


def valid_host(host):
    if not isinstance(host, str) or len(host) > 253:
        return False

    labels = host.split(".")

    if len(labels) < 2:
        return False

    pattern = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"

    return all(
        re.fullmatch(pattern, label)
        for label in labels
    )


def context(target, run_id):
    if not re.fullmatch(r"(T1|T2|P1|P2)", target):
        raise ValueError(
            "Identificador de target no permitido"
        )

    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", run_id):
        raise ValueError(
            "Identificador de corrida invalido"
        )

    config = json.loads(
        (ROOT / "scope.json").read_text(encoding="utf-8")
    )

    scope = config[target]

    if scope.get("authorized") is not True:
        raise ValueError(
            "Target sin autorizacion declarada en scope.json"
        )

    domain = scope["domain"]

    if not valid_host(domain):
        raise ValueError("Dominio base invalido")

    if scope["mode"] not in ("lab", "public"):
        raise ValueError("Modalidad invalida")

    if scope["scheme"] not in ("http", "https"):
        raise ValueError("Protocolo invalido")

    if (
        type(scope["port"]) is not int
        or not 1 <= scope["port"] <= 65535
    ):
        raise ValueError("Puerto invalido")

    if not isinstance(scope["allowed_hosts"], list):
        raise ValueError(
            "allowed_hosts debe ser una lista"
        )

    for host in scope["allowed_hosts"]:
        if not valid_host(host):
            raise ValueError(
                "Nombre invalido en allowed_hosts"
            )

        if not (
            host == domain
            or host.endswith("." + domain)
        ):
            raise ValueError(
                "Host autorizado fuera del dominio base"
            )

    # Restricciones especificas de los laboratorios publicos.
    if scope["mode"] == "public":
        public_limits = {
            "P1": (
                "vulnweb.com",
                "http",
                80,
                {"testphp.vulnweb.com"}
            ),
            "P2": (
                "testfire.net",
                "https",
                443,
                {"demo.testfire.net"}
            )
        }

        expected = public_limits.get(target)

        if expected is None:
            raise ValueError(
                "Target publico no previsto"
            )

        if (
            scope["domain"],
            scope["scheme"],
            scope["port"]
        ) != expected[:3]:
            raise ValueError(
                "Dominio, protocolo o puerto fuera "
                "del alcance publico"
            )

        if not set(scope["allowed_hosts"]).issubset(
            expected[3]
        ):
            raise ValueError(
                "Hosts fuera del alcance publico del trabajo"
            )

    return scope, EVIDENCE / target / run_id


def run_tool(args, timeout, input_text=None):
    start = time.monotonic()

    try:
        process = subprocess.run(
            args,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )

        result = {
            "status": (
                "ok" if process.returncode == 0 else "error"
            ),
            "returncode": process.returncode,
            "stdout": process.stdout,
            "stderr": process.stderr
        }

    except subprocess.TimeoutExpired as error:
        def as_text(value):
            if isinstance(value, bytes):
                return value.decode(
                    "utf-8",
                    errors="replace"
                )

            return value or ""

        result = {
            "status": "timeout",
            "returncode": None,
            "stdout": as_text(error.stdout),
            "stderr": as_text(error.stderr)
        }

    except OSError as error:
        result = {
            "status": "error",
            "returncode": None,
            "stdout": "",
            "stderr": str(error)
        }

    result["duration_ms"] = round(
        (time.monotonic() - start) * 1000
    )

    return result


def collect(target, run_id):
    scope, folder = context(target, run_id)

    if scope["mode"] == "public":
        return collect_public(target, run_id)

    # Modalidad de laboratorio: leer el fixture.
    start = time.monotonic()

    fixture = ROOT / "fixtures" / (target + ".json")

    raw = json.loads(
        fixture.read_text(encoding="utf-8")
    )

    if not isinstance(raw, list):
        raise ValueError(
            "El fixture debe contener una lista"
        )

    for row in raw:
        if not isinstance(row, dict):
            raise ValueError(
                "Cada registro debe ser un objeto JSON"
            )

        if (
            not isinstance(row.get("value"), str)
            or not isinstance(row.get("source"), str)
        ):
            raise ValueError(
                "Cada registro requiere value y source "
                "como textos"
            )

    folder.mkdir(parents=True, exist_ok=False)

    sources = {
        "subfinder": {
            "status": "not_applicable",
            "duration_ms": 0
        },
        "crtsh": {
            "status": "not_applicable",
            "duration_ms": 0
        },
        "fixture": {
            "status": "synthetic",
            "duration_ms": 0
        }
    }

    report = {
        "target_id": target,
        "run_id": run_id,
        "scope": scope,
        "collected_at": dt.datetime.now(
            dt.timezone.utc
        ).isoformat(),
        "raw": raw,
        "sources": sources,
        "collection_ms": round(
            (time.monotonic() - start) * 1000
        )
    }

    save(folder / "collection.json", report)

    return report


def collect_public(target, run_id):
    scope, folder = context(target, run_id)

    start = time.monotonic()

    started_at = dt.datetime.now(
        dt.timezone.utc
    ).isoformat()

    folder.mkdir(parents=True, exist_ok=False)

    raw = []
    sources = {}

    # 1. Enumeracion pasiva mediante Subfinder.
    command = [
        "/usr/local/bin/subfinder",
        "-d", scope["domain"],
        "-silent",
        "-json",
        "-cs",
        "-duc",
        "-rl", "2",
        "-timeout", "10",
        "-max-time", "2"
    ]

    process = run_tool(command, 150)

    errors = []
    found = []

    for number, line in enumerate(
        process["stdout"].splitlines(), 1
    ):
        if not line.strip():
            continue

        try:
            item = json.loads(line)

            if (
                not isinstance(item, dict)
                or not isinstance(item.get("host"), str)
            ):
                raise ValueError(
                    "Registro sin host de tipo texto"
                )

            found.append({
                "value": item["host"],
                "source": "subfinder",
                "providers": item.get(
                    "sources",
                    item.get("source", [])
                )
            })

        except (ValueError, TypeError) as error:
            errors.append({
                "line": number,
                "error": str(error)
            })

    save(folder / "subfinder_process.json", {
        **process,
        "command": command,
        "parse_errors": errors
    })

    sources["subfinder"] = {
        "status": (
            "partial"
            if process["status"] == "ok" and errors
            else process["status"]
        ),
        "duration_ms": process["duration_ms"],
        "records": len(found),
        "parse_errors": errors,
        "evidence_file": "subfinder_process.json"
    }

    raw.extend(found)

    # 2. Consulta a crt.sh.
    query = urlencode({
        "q": "%." + scope["domain"],
        "output": "json"
    })

    url = "https://crt.sh/?" + query

    # Este texto es un programa separado.
    # Su contenido comienza desde el margen izquierdo.
    fetch_code = """
import sys
import urllib.request

request = urllib.request.Request(
    sys.argv[1],
    headers={"User-Agent": "TI1-recon/1.0"}
)

with urllib.request.urlopen(request, timeout=30) as response:
    body = response.read(10_000_001)

if len(body) > 10_000_000:
    raise ValueError(
        "Respuesta mayor a 10 MB: no se procesara truncada"
    )

sys.stdout.buffer.write(body)
"""

    process = run_tool(
        [sys.executable, "-c", fetch_code, url],
        45
    )

    errors = []
    found = []

    if process["stdout"].strip():
        try:
            certificates = json.loads(
                process["stdout"]
            )

            if not isinstance(certificates, list):
                raise ValueError(
                    "crt.sh no devolvio una lista JSON"
                )

            for index, certificate in enumerate(
                certificates
            ):
                if (
                    not isinstance(certificate, dict)
                    or not isinstance(
                        certificate.get("name_value"),
                        str
                    )
                ):
                    errors.append({
                        "record": index,
                        "error": "Registro sin name_value"
                    })
                    continue

                for name in certificate[
                    "name_value"
                ].splitlines():
                    if name.strip():
                        found.append({
                            "value": name,
                            "source": "crtsh",
                            "certificate_id": certificate.get(
                                "id"
                            )
                        })

        except (ValueError, TypeError) as error:
            errors.append({
                "error": str(error)
            })

    elif process["status"] == "ok":
        errors.append({
            "error": (
                "Respuesta vacia: se esperaba una lista JSON"
            )
        })

    save(folder / "crtsh_process.json", {
        **process,
        "query_url": url,
        "parse_errors": errors
    })

    sources["crtsh"] = {
        "status": (
            "partial"
            if process["status"] == "ok" and errors
            else process["status"]
        ),
        "duration_ms": process["duration_ms"],
        "records": len(found),
        "parse_errors": errors,
        "evidence_file": "crtsh_process.json"
    }

    raw.extend(found)

    # 3. Hosts conocidos: no se atribuyen al discovery.
    for host in scope["allowed_hosts"]:
        raw.append({
            "value": host,
            "source": "provided_target"
        })

    report = {
        "target_id": target,
        "run_id": run_id,
        "scope": scope,
        "collection_started_at": started_at,
        "collected_at": dt.datetime.now(
            dt.timezone.utc
        ).isoformat(),
        "collection_status": (
            "completed"
            if all(
                item["status"] == "ok"
                for item in sources.values()
            )
            else "partial"
        ),
        "raw": raw,
        "sources": sources,
        "provided_targets": scope["allowed_hosts"],
        "collection_ms": round(
            (time.monotonic() - start) * 1000
        )
    }

    save(folder / "collection.json", report)

    return report


def probe(encoded):
    start = time.monotonic()

    # Recuperar y validar los datos recibidos.
    if len(encoded) > 60000:
        raise ValueError(
            "Payload demasiado grande"
        )

    data = json.loads(
        base64.b64decode(
            encoded,
            validate=True
        ).decode("utf-8")
    )

    if not isinstance(data, dict):
        raise ValueError(
            "El payload debe ser un objeto JSON"
        )

    scope, folder = context(
        data["target_id"],
        data["run_id"]
    )

    collection = json.loads(
        (folder / "collection.json").read_text(
            encoding="utf-8"
        )
    )

    if collection["scope"] != scope:
        raise ValueError(
            "El alcance cambio: iniciar una corrida nueva"
        )

    hosts = data.get("hosts")

    if (
        not isinstance(hosts, list)
        or not 1 <= len(hosts) <= 500
    ):
        raise ValueError(
            "Se requieren entre 1 y 500 hosts"
        )

    seen = set()

    for item in hosts:
        host = (
            item.get("host")
            if isinstance(item, dict)
            else None
        )

        if (
            not valid_host(host)
            or host not in scope["allowed_hosts"]
        ):
            raise ValueError(
                "Host invalido o no autorizado"
            )

        if host in seen:
            raise ValueError(
                "La lista contiene hosts repetidos"
            )

        seen.add(host)

    save(folder / "normalized.json", data)

    # Resolver exclusivamente los hosts autorizados.
    dns_code = (
        "import socket,json,sys; "
        "print(json.dumps(sorted({r[4][0] for r in "
        "socket.getaddrinfo("
        "sys.argv[1],None,0,socket.SOCK_STREAM"
        ")})))"
    )

    records = []
    dns_results = {}
    urls = []

    for item in hosts:
        host = item["host"]

        url = (
            f"{scope['scheme']}://"
            f"{host}:{scope['port']}/"
        )

        dns = run_tool(
            [sys.executable, "-c", dns_code, host],
            6
        )

        dns_results[host] = dns

        ips = (
            json.loads(dns["stdout"])
            if dns["status"] == "ok"
            else []
        )

        resolved = bool(ips)

        records.append({
            "host": host,
            "sources": item.get("sources", []),
            "requested_url": url,
            "ips": ips,
            "dns_status": (
                "resolved"
                if resolved
                else dns["status"]
            ),
            "http_state": (
                "pending"
                if resolved
                else "not_checked_dns_error"
            ),
            "http_status": None,
            "http_observed": False
        })

        if resolved:
            urls.append(url)

    save(folder / "dns.json", dns_results)

    (folder / "urls.txt").write_text(
        "\n".join(urls),
        encoding="utf-8"
    )

    # HTTPX respeta el protocolo de entrada.
    # No se habilita seguimiento de redirecciones.
    command = [
        "/usr/local/bin/httpx",
        "-silent",
        "-json",
        "-no-color",
        "-status-code",
        "-title",
        "-server",
        "-tech-detect",
        "-ip",
        "-response-time",
        "-nfs",
        "-duc",
        "-threads", "2",
        "-rl", "2",
        "-timeout", "5",
        "-retries", "0"
    ]

    if urls:
        httpx = run_tool(
            command,
            300,
            "\n".join(urls) + "\n"
        )

    else:
        httpx = {
            "status": "skipped",
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "duration_ms": 0
        }

    httpx["command"] = command

    save(folder / "httpx_process.json", httpx)

    submitted = {
        row["host"]
        for row in records
        if row["ips"]
    }

    observations = {}
    parse_errors = []

    for number, line in enumerate(
        httpx["stdout"].splitlines(), 1
    ):
        if not line.strip():
            continue

        try:
            result = json.loads(line)

            address = (
                result.get("input")
                or result.get("url")
            )

            host = urlsplit(
                address
                if "://" in address
                else "//" + address
            ).hostname

            if host not in submitted:
                raise ValueError(
                    "Respuesta sin correspondencia "
                    "con los hosts enviados"
                )

            observations[host] = result

        except (
            ValueError,
            TypeError,
            AttributeError
        ) as error:
            parse_errors.append({
                "line": number,
                "error": str(error)
            })

    tool_problem = (
        httpx["status"] in ("error", "timeout")
        or bool(parse_errors)
    )

    # Conservar un registro por cada host recibido.
    for row in records:
        if not row["ips"]:
            continue

        result = observations.get(
            row["host"],
            {}
        )

        code = result.get("status_code")

        if type(code) is int and 100 <= code <= 599:
            row.update({
                "http_state": "response",
                "http_status": code,
                "http_observed": True,
                "title": result.get("title"),
                "webserver": result.get("webserver"),
                "tech": result.get("tech", []),
                "response_time": result.get("time")
            })

        else:
            row["http_state"] = (
                "inconclusive"
                if tool_problem
                else "no_response_observed"
            )

    # Una comprobacion HTTP correcta no oculta
    # una recoleccion publica parcial.
    collection_problem = (
        collection.get("collection_status") == "partial"
    )

    report = {
        **data,
        "scope": scope,
        "sources": collection["sources"],
        "collection_ms": collection["collection_ms"],
        "status": (
            "partial"
            if tool_problem or collection_problem
            else "completed"
        ),
        "check_performed": True,
        "records": records,
        "httpx_status": httpx["status"],
        "parse_errors": parse_errors,
        "dns_ms": sum(
            item["duration_ms"]
            for item in dns_results.values()
        ),
        "httpx_ms": httpx["duration_ms"],
        "probe_ms": round(
            (time.monotonic() - start) * 1000
        ),
        "finished_at": dt.datetime.now(
            dt.timezone.utc
        ).isoformat()
    }

    save(folder / "result_worker.json", report)

    return report


if __name__ == "__main__":
    try:
        if (
            len(sys.argv) == 4
            and sys.argv[1] == "collect"
        ):
            output = collect(
                sys.argv[2],
                sys.argv[3]
            )

        elif (
            len(sys.argv) == 3
            and sys.argv[1] == "probe"
        ):
            output = probe(sys.argv[2])

        else:
            raise ValueError(
                "Uso: recon.py collect TARGET RUN_ID "
                "o recon.py probe PAYLOAD_BASE64"
            )

    except Exception as error:
        output = {
            "fatal": str(error)
        }

    print(
        json.dumps(
            output,
            ensure_ascii=False
        )
    )