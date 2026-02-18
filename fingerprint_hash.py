#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
fingerprint_hash.py

Gera uma assinatura (hash) determinística a partir do CANON_STRING produzido pela canonização.

Regra:
  HASH = sha256( CANON_STRING em UTF-8 )

Uso:
  python fingerprint_hash.py bundle.json
  python fingerprint_hash.py bundle.json --outdir runs/.../fp
  python fingerprint_hash.py bundle.json --algo sha256
  python fingerprint_hash.py bundle.json --debug

"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from typing import Any, Dict

from canonicalize_features import build_canon, dumps_canon


def compute_hash_from_canon_string(canon_string: str, algo: str = "sha256") -> str:
    """
    Hash determinístico do CANON_STRING puro.
    """
    algo = (algo or "sha256").lower().strip()
    if algo not in hashlib.algorithms_available:
        raise ValueError(f"Algoritmo '{algo}' não suportado. Use algo disponível em hashlib.")

    h = hashlib.new(algo)
    h.update(canon_string.encode("utf-8"))
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("bundle_json", help="Caminho do bundle JSON (ex: bundle.json)")
    ap.add_argument("--policy", choices=["stable", "rich"], default="stable",
                    help="stable = conservador; rich = inclui mais campos")
    ap.add_argument("--algo", default="sha256",
                    help="Algoritmo hashlib (ex: sha256, sha1, blake2b, sha3_256...)")
    ap.add_argument("--outdir", default=None,
                    help="Se fornecido, salva fingerprint.txt e fingerprint.json nesse diretório")
    ap.add_argument("--debug", action="store_true",
                    help="Imprime diagnósticos (repr, tamanhos e hash dos bytes) para confirmar estabilidade")
    args = ap.parse_args()

    with open(args.bundle_json, "r", encoding="utf-8") as f:
        bundle: Dict[str, Any] = json.load(f)

    canon_obj = build_canon(bundle, policy=args.policy)
    canon_string = dumps_canon(canon_obj)

    fp_hash = compute_hash_from_canon_string(canon_string, algo=args.algo)

    print("\n=== CANON_STRING ===")
    print(canon_string)

    if args.debug:
        b = canon_string.encode("utf-8")
        print("\n=== DEBUG ===")
        print("repr:", repr(canon_string))
        print("len(chars):", len(canon_string))
        print("len(bytes):", len(b))
        print("sha256(bytes):", hashlib.sha256(b).hexdigest())

    print("\n=== FINGERPRINT_HASH ===")
    print(fp_hash)

    if args.outdir:
        os.makedirs(args.outdir, exist_ok=True)

        out_txt = os.path.join(args.outdir, "fingerprint.txt")
        out_json = os.path.join(args.outdir, "fingerprint.json")

        with open(out_txt, "w", encoding="utf-8", newline="\n") as f:
            f.write(fp_hash + "\n")

        payload = {
            "algo": args.algo,
            "policy": args.policy,
            "fingerprint": fp_hash,
        }
        with open(out_json, "w", encoding="utf-8", newline="\n") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2, sort_keys=True)

        print(f"\n[OK] Saved:\n- {out_txt}\n- {out_json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
