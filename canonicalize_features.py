#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
canonicalize_features.py

Lê um bundle JSON (ex.: fingerprint.json / bundle.json) e gera:
- CANON_OBJ (objeto canônico)
- CANON_STRING (JSON minificado, ordenado e determinístico)

Política padrão: CONSERVADORA (estável)
- Evita campos notoriamente variáveis (ex.: versões detalhadas)
- Usa fallback quando nmap "stable fields" não aparece (ex.: iOS detectado)
- Usa fallback via PCAP SYN (tshark) quando p0f não gera blocos

ATUALIZAÇÕES (últimas alterações):
- Remove MTU totalmente (não entra no CANON)
- Remove network_distance do CANON (não ajuda a diferenciar em LAN)
- raw_sig do p0f vira campo obrigatório:
    * Se houver SERVER syn+ack (alvo respondeu), usa server_synack_raw_sig_set
    * Senão, usa client_syn_raw_sig_set
- Nmap vira opcional: só entra quando houver tcpip_stable_fields_raw válido
"""

from __future__ import annotations

import argparse
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

# -----------------------------
# Helpers: normalização / ordenação
# -----------------------------

_WS_RE = re.compile(r"\s+")


def norm_ws(s: str) -> str:
    """Normaliza whitespace: trim + colapsa múltiplos espaços."""
    s = s.strip()
    s = _WS_RE.sub(" ", s)
    return s


def is_nmap_ports_header(line: str) -> bool:
    """Detecta headers típicos do Nmap em tabela de portas."""
    t = norm_ws(line).upper()
    if t.startswith("PORT ") and "STATE" in t and "SERVICE" in t:
        return True
    if t == "PORT STATE SERVICE VERSION":
        return True
    return False


def parse_nmap_port_line(line: str) -> Optional[Tuple[str, str, str, str]]:
    """
    Parseia linha normalizada do Nmap em:
      (port_proto, state, service, version_rest)
    """
    line = norm_ws(line)
    if not line or is_nmap_ports_header(line):
        return None

    parts = line.split(" ")
    if len(parts) < 3:
        return None

    port_proto = parts[0]
    state = parts[1]
    service = parts[2]
    version_rest = " ".join(parts[3:]) if len(parts) > 3 else ""
    return (port_proto, state, service, version_rest)


def canonicalize_nmap_ports(
    ports_table_raw: List[str],
    include_ports: bool,
    include_versions: bool,
) -> Optional[List[str]]:
    """
    Retorna lista canônica de portas.
    - Remove headers
    - Normaliza whitespace
    - Ordena
    - Se include_versions=False: mantém só "port/proto state service"
    - Se include_versions=True: mantém linha completa normalizada (mais instável)
    """
    if not include_ports:
        return None

    rows: List[str] = []
    for raw in ports_table_raw or []:
        if not isinstance(raw, str):
            continue
        if is_nmap_ports_header(raw):
            continue

        parsed = parse_nmap_port_line(raw)
        if not parsed:
            continue
        port_proto, state, service, version_rest = parsed

        if include_versions and version_rest:
            rows.append(norm_ws(f"{port_proto} {state} {service} {version_rest}"))
        else:
            rows.append(norm_ws(f"{port_proto} {state} {service}"))

    rows = sorted(set(rows))
    return rows


def stable_list(items: List[Any]) -> List[str]:
    """Normaliza e ordena uma lista de strings de forma determinística."""
    out: List[str] = []
    for x in items or []:
        if isinstance(x, str):
            x2 = norm_ws(x)
            if x2:
                out.append(x2)
    return sorted(set(out))


def stable_str(x: Any) -> Optional[str]:
    """Normaliza string (ou None)."""
    if not isinstance(x, str):
        return None
    x2 = norm_ws(x)
    return x2 if x2 else None


def is_placeholder_not_captured(x: str) -> bool:
    """
    Detecta placeholders tipo "<não capturado>" que podem aparecer em versões antigas.
    """
    t = norm_ws(x).lower()
    return ("não capturado" in t) or ("nao capturado" in t) or (t == "<nao capturado>") or (t == "<não capturado>")


def prune_none(obj: Any) -> Any:
    """Remove chaves None e listas vazias recursivamente."""
    if isinstance(obj, dict):
        new = {}
        for k, v in obj.items():
            v2 = prune_none(v)
            if v2 is None:
                continue
            if isinstance(v2, dict) and not v2:
                continue
            if isinstance(v2, list) and not v2:
                continue
            new[k] = v2
        return new
    if isinstance(obj, list):
        new_list = [prune_none(v) for v in obj]
        new_list = [v for v in new_list if v is not None]
        return new_list
    return obj


def dumps_canon(obj: Dict[str, Any]) -> str:
    """
    Serializa com:
    - chaves ordenadas
    - sem espaços
    - unicode preservado
    """
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


# -----------------------------
# Canonização por política
# -----------------------------

def build_canon(bundle: Dict[str, Any], policy: str) -> Dict[str, Any]:
    """
    policy:
      - "stable" (padrão): assinatura conservadora
      - "rich": mais campos (ainda com limpeza), mas mais risco de variar
    """
    policy = (policy or "stable").lower().strip()
    if policy not in ("stable", "rich"):
        policy = "stable"

    include_ports = (policy == "rich")
    include_versions = False  # manter falso por padrão

    # -------- NMAP (opcional; só entra se tcpip stable existir) --------
    nmap = bundle.get("nmap", {}) if isinstance(bundle.get("nmap"), dict) else {}

    tcpip_stable = stable_list(nmap.get("tcpip_stable_fields_raw", []))
    tcpip_stable = [x for x in tcpip_stable if not is_placeholder_not_captured(x)]

    host_scripts = stable_list(nmap.get("host_script_results_raw", []))
    service_info = stable_str(nmap.get("service_info"))

    ports_canon = canonicalize_nmap_ports(
        ports_table_raw=nmap.get("ports_table_raw", []) if isinstance(nmap.get("ports_table_raw"), list) else [],
        include_ports=include_ports,
        include_versions=include_versions,
    )

    mac_address = stable_str(nmap.get("mac_address"))

    nmap_canon: Dict[str, Any] = {}
    if tcpip_stable:
        nmap_canon["tcpip_stable_fields_raw"] = tcpip_stable

    if policy == "rich":
        # Ainda opcional: só faz sentido ter esses extras se existir algum sinal do nmap no canon.
        if nmap_canon:
            nmap_canon["service_info"] = service_info
            nmap_canon["host_script_results_raw"] = host_scripts or None
            nmap_canon["ports"] = ports_canon
            nmap_canon["mac_address"] = mac_address

    # -------- P0F (raw_sig obrigatório; MTU removido) --------
    p0f = bundle.get("p0f", {}) if isinstance(bundle.get("p0f"), dict) else {}
    extracted = p0f.get("extracted", {}) if isinstance(p0f.get("extracted"), dict) else {}

    # Refinamento:
    # - Se houver dados do ALVO como SERVER (syn+ack), priorizamos SERVER e ignoramos CLIENT,
    #   porque no seu fluxo (nping/nmap a partir do PC) o "client" costuma ser o PC.
    client_sig = stable_list(extracted.get("client_syn_raw_sig_set", []))
    server_sig = stable_list(extracted.get("server_synack_raw_sig_set", []))

    has_server = bool(server_sig)

    if has_server:
        p0f_extracted = {"server_synack_raw_sig_set": server_sig or None}
        rawsig_present = bool(server_sig)
    else:
        p0f_extracted = {"client_syn_raw_sig_set": client_sig or None}
        rawsig_present = bool(client_sig)

    # -------- PCAP SYN (fallback tshark) --------
    pcap_syn = bundle.get("pcap_syn", {}) if isinstance(bundle.get("pcap_syn"), dict) else {}
    pcap_syn_canon = None

    if pcap_syn and not pcap_syn.get("skipped"):
        pcap_syn_canon = {
            "ttl": stable_str(pcap_syn.get("ttl")),
            "window_size": stable_str(pcap_syn.get("window_size")),
            "mss": stable_str(pcap_syn.get("mss")),
            "ws": stable_str(pcap_syn.get("ws")),
            "sack_perm": stable_str(pcap_syn.get("sack_perm")),
            "ts_present": stable_str(pcap_syn.get("ts_present")),
            "options_order": stable_str(pcap_syn.get("options_order")),
        }
        pcap_syn_canon = prune_none(pcap_syn_canon)

    # Se p0f não trouxe raw_sig, tenta usar pcap_syn como fallback mínimo (se existir).
    # (Você pediu raw_sig obrigatório; aqui garantimos que "não sai fingerprint vazio".)
    if not rawsig_present and pcap_syn_canon:
        # Mantém apenas um subconjunto bem estável da SYN, para não inflar.
        pcap_syn_min = prune_none({
            "ttl": pcap_syn_canon.get("ttl"),
            "mss": pcap_syn_canon.get("mss"),
            "ws": pcap_syn_canon.get("ws"),
            "sack_perm": pcap_syn_canon.get("sack_perm"),
            "ts_present": pcap_syn_canon.get("ts_present"),
            "options_order": pcap_syn_canon.get("options_order"),
        })
        canon: Dict[str, Any] = {
            "p0f": {"extracted": prune_none(p0f_extracted)},
            "pcap_syn": pcap_syn_min,
        }
        if nmap_canon:
            canon["nmap"] = nmap_canon
        return prune_none(canon)

    # Se ainda assim não tem raw_sig, retorna erro explícito (melhor que {} silencioso).
    if not rawsig_present:
        raise ValueError(
            "Fingerprint inválido: p0f não gerou raw_sig do alvo (nem server syn+ack nem client syn). "
            "Sugestão: garantir que o alvo responda a SYN (porta aberta) ou habilitar fallback pcap_syn na captura."
        )

    # -----------------------------
    # Canon final
    # -----------------------------
    canon: Dict[str, Any] = {
        "p0f": {"extracted": prune_none(p0f_extracted)},
        "pcap_syn": pcap_syn_canon if pcap_syn_canon else None,
    }
    if nmap_canon:
        canon["nmap"] = nmap_canon

    return prune_none(canon)


# -----------------------------
# CLI
# -----------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("bundle_json", help="Caminho do bundle JSON (ex: fingerprint.json/bundle.json)")
    ap.add_argument("--policy", choices=["stable", "rich"], default="stable",
                    help="stable = conservador; rich = inclui mais campos")
    ap.add_argument("--outdir", default=None,
                    help="Se fornecido, salva features_canon.json e features_canon.txt nesse diretório")
    args = ap.parse_args()

    with open(args.bundle_json, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    canon_obj = build_canon(bundle, policy=args.policy)
    canon_str = dumps_canon(canon_obj)

    print("\n=== CANON_OBJ ===")
    print(json.dumps(canon_obj, ensure_ascii=False, sort_keys=True, indent=2))

    print("\n=== CANON_STRING ===")
    print(canon_str)

    if args.outdir:
        os.makedirs(args.outdir, exist_ok=True)
        out_json = os.path.join(args.outdir, "features_canon.json")
        out_txt = os.path.join(args.outdir, "features_canon.txt")
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(canon_obj, f, ensure_ascii=False, sort_keys=True, indent=2)
        with open(out_txt, "w", encoding="utf-8") as f:
            f.write(canon_str + "\n")
        print(f"\n[OK] Saved:\n- {out_json}\n- {out_txt}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
