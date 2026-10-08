import datetime as dt
import json
import os
from pathlib import Path
import re
import sys
import time

import base64
import subprocess
from urllib.parse import urlsplit


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
        raise ValueError("Identificador de target no permitido")

    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", run_id):
        raise ValueError("Identificador de corrida invalido")

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
        raise ValueError("allowed_hosts debe ser una lista")

    for host in scope["allowed_hosts"]:
        if not valid_host(host):
            raise ValueError("Nombre invalido en allowed_hosts")

        if not (
            host == domain
            or host.endswith("." + domain)
        ):
            raise ValueError(
                "Host autorizado fuera del dominio base"
            )

    return scope, EVIDENCE / target / run_id


def collect(target, run_id):
    scope, folder = context(target, run_id)

    if scope["mode"] != "lab":
        raise ValueError(
            "La recoleccion publica aun no esta implementada"
        )

    start = time.monotonic()

    fixture = ROOT / "fixtures" / (target + ".json")

    raw = json.loads(
        fixture.read_text(encoding="utf-8")
    )

    if not isinstance(raw, list):
        raise ValueError("El fixture debe contener una lista")

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
                "Cada registro requiere value y source como textos"
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
            "status": "ok" if process.returncode == 0 else "error",
            "returncode": process.returncode,
            "stdout": process.stdout,
            "stderr": process.stderr
        }

    except subprocess.TimeoutExpired as error:
        def as_text(value):
            if isinstance(value, bytes):
                return value.decode("utf-8", errors="replace")
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


def probe(encoded):
    start = time.monotonic()

    # Recuperar y validar los datos recibidos.
    if len(encoded) > 60000:
        raise ValueError("Payload demasiado grande")

    data = json.loads(
        base64.b64decode(encoded, validate=True).decode("utf-8")
    )

    if not isinstance(data, dict):
        raise ValueError("El payload debe ser un objeto JSON")

    scope, folder = context(data["target_id"], data["run_id"])

    collection = json.loads(
        (folder / "collection.json").read_text(encoding="utf-8")
    )

    if collection["scope"] != scope:
        raise ValueError(
            "El alcance cambio: iniciar una corrida nueva"
        )

    hosts = data.get("hosts")

    if not isinstance(hosts, list) or not 1 <= len(hosts) <= 500:
        raise ValueError("Se requieren entre 1 y 500 hosts")

    seen = set()

    for item in hosts:
        host = item.get("host") if isinstance(item, dict) else None

        if not valid_host(host) or host not in scope["allowed_hosts"]:
            raise ValueError("Host invalido o no autorizado")

        if host in seen:
            raise ValueError("La lista contiene hosts repetidos")

        seen.add(host)

    save(folder / "normalized.json", data)

    # Resolver los nombres mediante el sistema del trabajador.
    dns_code = (
        "import socket,json,sys; "
        "print(json.dumps(sorted({r[4][0] for r in "
        "socket.getaddrinfo(sys.argv[1],None,0,socket.SOCK_STREAM)})))"
    )

    records = []
    dns_results = {}
    urls = []

    for item in hosts:
        host = item["host"]
        url = f"{scope['scheme']}://{host}:{scope['port']}/"

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
            "dns_status": "resolved" if resolved else dns["status"],
            "http_state": (
                "pending" if resolved else "not_checked_dns_error"
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

    # Comprobar únicamente las URLs construidas desde el alcance.
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

    save(folder / "httpx_process.json", httpx)

    # Relacionar cada respuesta con un host enviado.
    submitted = {
        row["host"] for row in records if row["ips"]
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
            address = result.get("input") or result.get("url")

            host = urlsplit(
                address if "://" in address else "//" + address
            ).hostname

            if host not in submitted:
                raise ValueError(
                    "Respuesta sin correspondencia con los hosts enviados"
                )

            observations[host] = result

        except (ValueError, TypeError, AttributeError) as error:
            parse_errors.append({
                "line": number,
                "error": str(error)
            })

    tool_problem = (
        httpx["status"] in ("error", "timeout")
        or bool(parse_errors)
    )

    # Conservar también los hosts que no produjeron respuestas.
    for row in records:
        if not row["ips"]:
            continue

        result = observations.get(row["host"], {})
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

    report = {
        **data,
        "scope": scope,
        "sources": collection["sources"],
        "collection_ms": collection["collection_ms"],
        "status": "partial" if tool_problem else "completed",
        "check_performed": True,
        "records": records,
        "httpx_status": httpx["status"],
        "parse_errors": parse_errors,
        "dns_ms": sum(
            item["duration_ms"] for item in dns_results.values()
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
        if len(sys.argv) == 4 and sys.argv[1] == "collect":
            output = collect(sys.argv[2], sys.argv[3])

        elif len(sys.argv) == 3 and sys.argv[1] == "probe":
            output = probe(sys.argv[2])

        else:
            raise ValueError(
                "Uso: recon.py collect TARGET RUN_ID "
                "o recon.py probe PAYLOAD_BASE64"
            )

    except Exception as error:
        output = {"fatal": str(error)}

    print(json.dumps(output, ensure_ascii=False))