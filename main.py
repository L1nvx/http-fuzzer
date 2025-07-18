import httpx
import logging
import json
import difflib
import hashlib
import copy
import argparse
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
from rich.theme import Theme
from rich.box import ROUNDED
from urllib.parse import quote_plus
from urllib.parse import parse_qs
from rich.box import DOUBLE, SIMPLE_HEAD, MINIMAL
from urllib.parse import unquote
from time import sleep

custom_theme = Theme({
    "info": "bold cyan",
    "warning": "bold yellow",
    "danger": "bold red",
    "success": "bold green",
    "header": "bold reverse",
    "key": "bold magenta",
    "value": "bright_white"
})
console = Console(theme=custom_theme)


def mostrar_diffs_con_rich(diffs, payload, location, method, url, content_type):
    CONTEXT_STYLE = "bold #3498db"
    HEADER_STYLE = "bold #9b59b6"
    PAYLOAD_STYLE = "bold #f39c12"
    BODY_DIFF_STYLE = "bold #e74c3c"

    console.clear()

    console.rule(f"[{CONTEXT_STYLE}]📤 DETECTED DIFFERENCES",
                 style=CONTEXT_STYLE)
    console.print(
        f"[bold]{method}[/] [dim]|[/] [link={url}]{url}[/]\n"
        f"[dim]Content-Type:[/] {content_type}\n",
        justify="center"
    )

    console.rule(f"[{HEADER_STYLE}]📥 MODIFIED HEADERS",
                 style=HEADER_STYLE)
    if "headers" in diffs and diffs["headers"]:
        table = Table(
            box=ROUNDED,
            header_style="bold magenta",
            expand=True,
            width=min(100, console.width - 10)
        )
        table.add_column("Cabecera", style="bold cyan", min_width=15)
        table.add_column("Original", style="green",
                         min_width=25, overflow="fold")
        table.add_column("Modificado", style="red",
                         min_width=25, overflow="fold")

        for header, values in diffs["headers"].items():
            orig = str(values[0])
            mod = str(values[1])

            if len(orig) > 50:
                orig = orig[:50] + "..."
            if len(mod) > 50:
                mod = mod[:50] + "..."

            table.add_row(header, orig, mod)

        console.print(table)
    else:
        console.print(
            "[dim]No differences detected in the headers.[/]", justify="center")
    console.print()

    console.rule(f"[{PAYLOAD_STYLE}]📦 PAYLOAD SENT", style=PAYLOAD_STYLE)
    if payload:
        payload_str = json.dumps(payload, indent=2) if isinstance(
            payload, dict) else str(payload)

        if isinstance(payload, dict):
            console.print(
                Syntax(payload_str, "json", theme="monokai",
                       line_numbers=False, word_wrap=True),
            )
        else:
            try:
                decoded_payload = unquote(payload_str)
                console.print(Panel(
                    decoded_payload,
                    style=PAYLOAD_STYLE,
                    box=ROUNDED,
                    expand=False,
                    width=min(100, console.width - 10)
                ))
            except:
                console.print(Panel(
                    payload_str,
                    style=PAYLOAD_STYLE,
                    box=ROUNDED,
                    expand=False,
                    width=min(100, console.width - 10)
                ))
    else:
        console.print("[dim]No payload was sent.[/]", justify="center")
    console.print()

    console.rule(
        f"[{BODY_DIFF_STYLE}]🧾 DIFFERENCES IN THE BODY", style=BODY_DIFF_STYLE)
    if "body_diff" in diffs and diffs["body_diff"]:
        console.print(Panel(
            Syntax(diffs["body_diff"], "diff", theme="github-dark",
                   line_numbers=True, word_wrap=True),
            box=ROUNDED,
            style=BODY_DIFF_STYLE
        ))
    else:
        console.print(
            "[dim]No differences detected in the body.[/]", justify="center")
    console.print()

    # pie
    console.rule(style="dim")
    sleep(0.5)


logging.basicConfig(
    level=logging.WARN,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger(__name__)


def comparar_respuestas(resp1, resp2, ignorar_headers=None):
    if ignorar_headers is None:
        ignorar_headers = {"date", "opc-request-id",
                           "x-oracle-ics-instance-id", "Strict-Transport-Security"}

    if resp2.status_code == 405:
        return {}

    diferencias = {}

    if resp1.status_code != resp2.status_code:
        diferencias["status_code"] = (resp1.status_code, resp2.status_code)

    headers_diff = {}
    all_keys = set(resp1.headers.keys()) | set(resp2.headers.keys())

    for key in all_keys:
        if key.lower() in ignorar_headers:
            continue
        val1 = resp1.headers.get(key)
        val2 = resp2.headers.get(key)
        if val1 != val2:
            headers_diff[key] = (val1, val2)

    if headers_diff:
        diferencias["headers"] = headers_diff

    if len(resp1.content) != len(resp2.content):
        diferencias["content_length"] = (
            len(resp1.content), len(resp2.content))

    hash1 = hashlib.md5(resp1.content).hexdigest()
    hash2 = hashlib.md5(resp2.content).hexdigest()
    if hash1 != hash2:
        diferencias["content_hash"] = (hash1, hash2)

    if resp1.text != resp2.text:
        diff = difflib.unified_diff(
            resp1.text.splitlines(),
            resp2.text.splitlines(),
            lineterm='',
            n=5
        )
        diferencias["body_diff"] = "\n".join(diff)

    if resp1.cookies != resp2.cookies:
        diferencias["cookies"] = (resp1.cookies, resp2.cookies)

    # if resp1.elapsed != resp2.elapsed:
    #     diferencias["elapsed"] = (
    #         resp1.elapsed.total_seconds(), resp2.elapsed.total_seconds())

    return diferencias


class Request:
    def __init__(self, rawRequest):
        self.method = None
        self.path = None
        self.parameters = {}
        self.httpVersion = None
        self.headers = {}
        self.body = {}

        self.rawRequest = rawRequest

    def parse_request(self):
        # method, path, parameters, http version
        line1 = self.rawRequest.split("\n")[0].split()

        if len(line1) != 3:
            raise ValueError(f"Invalid HTTP request line: {line1}")

        self.method = line1[0]
        uri = line1[1]

        if "?" in uri:
            # parameters in uri
            self.path = uri.split("?")[0]
            parameters = uri.split("?")[1]
            if "&" in parameters:
                self.parameters = {k: v[0] for k, v in parse_qs(
                    uri.split("?", 1)[1]).items()}
            else:
                key = parameters.split("=", 1)[0]
                value = parameters.split("=", 1)[1]
                self.parameters.update({
                    key: value
                })
        else:
            self.path = uri
        self.httpVersion = line1[2]

        # headers
        line_headers = self.rawRequest.split("\n")[1:]
        body_form = None
        body_json = None

        for words in line_headers:
            if ":" in words and "\":" not in words and "Content-Length" not in words:
                key, value = words.split(":", 1)

                if value.startswith(" "):
                    value = value[1:]

                if key == "Content-Type" and value == "application/x-www-form-urlencoded":
                    body_form = True

                if key == "Content-Type" and value == "application/json":
                    body_json = True

                self.headers.update({
                    key: value
                })

        # body parameters
        line_body = self.rawRequest.split("\n\n")[-1]
        if body_form:
            parsed = parse_qs(line_body)
            self.body = {k: v[0] for k, v in parsed.items()}

        elif body_json:
            self.body = json.loads(line_body)
        return self.method, self.path, self.parameters, self.httpVersion, self.headers, self.body


class Fuzzer:
    def __init__(self, requestFile, methods, content_types, proto, proxy, body_format="both"):
        self.requestFile = requestFile
        self.proto = proto + "://"
        self.proxy = proxy
        self.body_format = body_format.lower()

        self.rawRequest = None

        self.methods = methods
        self.content_types = content_types
        self.payloadsFile = "payloads.json"

        self.payloads = {}

        self.request = {}

    def dict_to_bodydata(self, obj, parent_key=''):
        data = []

        if isinstance(obj, dict):
            for key, value in obj.items():
                if parent_key:
                    new_key = f"{parent_key}[{key}]"
                else:
                    new_key = key

                if isinstance(value, (dict, list)):
                    data.append(self.dict_to_bodydata(value, new_key))
                else:
                    encoded_key = quote_plus(new_key)
                    encoded_value = quote_plus(str(value))
                    data.append(f"{encoded_key}={encoded_value}")

        elif isinstance(obj, list):
            for item in obj:
                new_key = f"{parent_key}[]"
                if isinstance(item, (dict, list)):
                    data.append(self.dict_to_bodydata(item, new_key))
                else:
                    encoded_key = quote_plus(new_key)
                    encoded_value = quote_plus(str(item))
                    data.append(f"{encoded_key}={encoded_value}")

        else:
            if parent_key:
                encoded_key = quote_plus(parent_key)
                encoded_value = quote_plus(str(obj))
                data.append(f"{encoded_key}={encoded_value}")

        return "&".join(data)

    def load_payloads(self):
        try:
            with open(self.payloadsFile, "r") as file:
                self.payloads = json.load(file)

        except Exception as err:
            log.error(err)
            return

    def load_request(self):
        try:
            with open(self.requestFile, "r") as file:
                self.rawRequest = file.read()

        except Exception as err:
            log.error(err)
            return

        self.request = Request(self.rawRequest)
        self.request.parse_request()

    def send_request(self, url, method, parameters, headers, body):
        try:
            if self.proxy:

                response = httpx.request(
                    url=url,
                    method=method,
                    params=parameters,
                    headers=headers,
                    content=body,
                    timeout=15,
                    proxy=self.proxy,
                    verify=False
                )
            else:
                response = httpx.request(
                    url=url,
                    method=method,
                    params=parameters,
                    headers=headers,
                    content=body,
                    timeout=15,
                    verify=False
                )
        except httpx.ReadTimeout as err:
            log.info(err)
            return None

        return response

    def generate_recursive_variations(self, data, payload):
        variations = []

        def recurse(obj, path):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    recurse(value, path + [key])
            elif isinstance(obj, list):
                for idx, item in enumerate(obj):
                    recurse(item, path + [idx])
            else:
                modified = copy.deepcopy(data)
                target = modified
                for p in path[:-1]:
                    target = target[p]
                target[path[-1]] = payload
                variations.append(modified)

        recurse(data, [])
        return variations

    def Main(self):
        self.load_request()
        self.load_payloads()
        # send original request
        url = self.proto + self.request.headers["Host"] + self.request.path

        log.info(f"Sending original request")

        if "Content-Type" in self.request.headers:
            if "json" in self.request.headers["Content-Type"]:
                original_response = self.send_request(
                    url=url,
                    method=self.request.method,
                    parameters=self.request.parameters,
                    headers=self.request.headers,
                    body=json.dumps(self.request.body),
                )
            elif "x-www-form-urlencoded" in self.request.headers["Content-Type"]:
                data = self.dict_to_bodydata(self.request.body)
                original_response = self.send_request(
                    url=url,
                    method=self.request.method,
                    parameters=self.request.parameters,
                    headers=self.request.headers,
                    body=data,
                )
        else:
            if not self.request.body:
                original_response = self.send_request(
                    url=url,
                    method=self.request.method,
                    parameters=self.request.parameters,
                    headers=self.request.headers,
                    body=None,
                )
            else:
                log.error("Unkown body type")

        method = ""
        parameters = {}
        headers = {}
        body = {}
        responses = []

        for method in self.methods:
            headers = self.request.headers.copy()
            for content_type in self.content_types or [None]:
                if content_type:
                    headers["Content-Type"] = content_type
                for payload_key, payload_list in self.payloads.items():
                    for current_payload in payload_list:
                        if self.request.parameters:
                            parameters = self.request.parameters.copy()
                            for param, value in parameters.items():
                                parameters[param] = current_payload

                                if not self.request.body:
                                    response = self.send_request(
                                        url=url,
                                        method=method,
                                        parameters=parameters,
                                        headers=headers,
                                        body=None
                                    )
                                    if response:
                                        diffs = comparar_respuestas(
                                            original_response, response)
                                        if diffs:
                                            mostrar_diffs_con_rich(
                                                diffs=diffs,
                                                payload=parameters,
                                                location="params",
                                                method=method,
                                                url=url,
                                                content_type=headers.get(
                                                    "Content-Type", "N/A")
                                            )
                                # Manejar solicitudes con cuerpo
                                else:
                                    # JSON
                                    if self.body_format in ["both", "json"]:
                                        response_json = self.send_request(
                                            url=url,
                                            method=method,
                                            parameters=parameters,
                                            headers=headers,
                                            body=json.dumps(self.request.body)
                                        )
                                        if response_json:
                                            diffs = comparar_respuestas(
                                                original_response, response_json)
                                            if diffs:
                                                mostrar_diffs_con_rich(
                                                    diffs=diffs,
                                                    payload=self.request.body,
                                                    location="params",
                                                    method=method,
                                                    url=url,
                                                    content_type=headers.get(
                                                        "Content-Type", "N/A")
                                                )

                                    # Form-data
                                    if self.body_format in ["both", "form"]:
                                        data = self.dict_to_bodydata(
                                            self.request.body)
                                        response_form = self.send_request(
                                            url=url,
                                            method=method,
                                            parameters=parameters,
                                            headers=headers,
                                            body=data
                                        )
                                        if response_form:
                                            diffs = comparar_respuestas(
                                                original_response, response_form)
                                            if diffs:
                                                mostrar_diffs_con_rich(
                                                    diffs=diffs,
                                                    payload=data,
                                                    location="params",
                                                    method=method,
                                                    url=url,
                                                    content_type=headers.get(
                                                        "Content-Type", "N/A")
                                                )

                                # Restaurar valor original
                                parameters[param] = value

                        if self.request.body:
                            variations = self.generate_recursive_variations(
                                self.request.body, current_payload)

                            for variation in variations:
                                # JSON
                                if self.body_format in ["both", "json"]:
                                    response_json = self.send_request(
                                        url=url,
                                        method=method,
                                        parameters=self.request.parameters,
                                        headers=headers,
                                        body=json.dumps(variation)
                                    )
                                    if response_json:
                                        diffs = comparar_respuestas(
                                            original_response, response_json)
                                        if diffs:
                                            mostrar_diffs_con_rich(
                                                diffs=diffs,
                                                payload=variation,
                                                location="body",
                                                method=method,
                                                url=url,
                                                content_type=headers.get(
                                                    "Content-Type", "N/A")
                                            )

                                # Form-data
                                if self.body_format in ["both", "form"]:
                                    data_body = self.dict_to_bodydata(
                                        variation)
                                    response_form = self.send_request(
                                        url=url,
                                        method=method,
                                        parameters=self.request.parameters,
                                        headers=headers,
                                        body=data_body
                                    )
                                    if response_form:
                                        diffs = comparar_respuestas(
                                            original_response, response_form)
                                        if diffs:
                                            mostrar_diffs_con_rich(
                                                diffs=diffs,
                                                payload=data_body,
                                                location="body",
                                                method=method,
                                                url=url,
                                                content_type=headers.get(
                                                    "Content-Type", "N/A")
                                            )


def main():
    parser = argparse.ArgumentParser(description="Fuzzer HTTP")

    parser.add_argument(
        "--requestFile",
        type=str,
        required=True,
        help="File containing the HTTP request"
    )

    parser.add_argument(
        "--methods",
        type=str,
        default="POST,PUT,PATCH,GET",
        help="HTTP methods to test (comma-separated), default: POST,PUT,PATCH,GET"
    )

    parser.add_argument(
        "--content_types",
        type=str,
        default=None,
        help="Content-Types to test (comma-separated), example: application/json,application/x-www-form-urlencoded; default: None"
    )

    parser.add_argument(
        "--proto",
        type=str,
        choices=["http", "https"],
        default="https",
        help="Protocol to use (http or https), default: https"
    )

    parser.add_argument(
        "--proxy",
        type=str,
        default=None,
        help="HTTP proxy to use, default: None"
    )

    parser.add_argument(
        "--body-format",
        type=str,
        choices=["both", "json", "form"],
        default="both",
        help="Formato del cuerpo: both (JSON y form-data), json, o form (default: both)"
    )

    args = parser.parse_args()

    methods_list = [m.strip().upper()
                    for m in args.methods.split(",") if args.methods and m.strip()]
    content_types_list = [c.strip()
                          for c in args.content_types.split(",")] if args.content_types else []

    fuzzer = Fuzzer(
        requestFile=args.requestFile,
        methods=methods_list,
        content_types=content_types_list,
        proto=args.proto,
        proxy=args.proxy,
        body_format=args.body_format
    )
    fuzzer.Main()


if __name__ == "__main__":
    main()
