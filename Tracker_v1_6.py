#!/usr/bin/env python3
"""
Multi-Layer Infra Tracker v1.6
pDNS + CT + HTTP Headers + ASN による関連性分析(防御・調査目的)

v1.5 レビューからの主な変更:
  - 認証情報の分離: CIRCL用セッションと調査対象用セッションを分け、Basic認証を対象へ送らない
  - 非公開IP・予約IPを除外 (ipaddress.is_global)
  - 古いIPには能動接続しない (--recent-days)
  - SNI=ドメイン名のまま指定IPへ接続 (Hostヘッダーだけでなく SNI も正しく送る)
  - リダイレクトを追わない / IPv6対応 / 本文は読まない
  - 「異なるドメイン × 1IPずつ」の決定論的サンプリング
  - 汎用Cookie/Serverは低配点、バージョン付きや固有値は高配点
  - ipinfo失敗は「判定不能」として扱い、加点しない
  - pDNS認証失敗を検出したら以降のpDNSを止め、現在のDNS解決へフォールバック
  - 出力の決定論化 (ソート)、pandas依存を削除

注意: 能動的なHTTP接続を伴う。自己管理下、または調査許可のあるインフラにのみ使うこと。
      --no-probe で受動情報(pDNS/CT/ASN)のみの実行ができる。
"""

import argparse
import http.client
import ipaddress
import json
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx
import requests

# --- 設定 ---
CIRCL_PDNS_URL = "https://www.circl.lu/pdns/query/"
CRT_SH_URL = "https://crt.sh/?q={}&output=json"
USER_AGENT = "InfraTracker/1.6"
REQUEST_TIMEOUT = 15
PROBE_TIMEOUT = 8
MAX_CT_DOMAINS = 30
MAX_HTTP_CHECKS = 30
MAX_DOMAINS_PER_CLUSTER = 6
DEFAULT_RECENT_DAYS = 90

PUBLIC_SUFFIX_2 = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.au", "net.au", "org.au", "gov.au", "edu.au",
    "co.nz", "org.nz", "net.nz",
    "com.br", "org.br", "net.br",
}

CLOUD_KEYWORDS = [
    "cloudflare", "amazon", "google", "fastly",
    "akamai", "microsoft", "incapsula", "cdn",
]

# 共有証明書・CDN由来のノイズ名
CT_NOISE_SUBSTRINGS = ("cloudflaressl.com", "sni.", "cloudflare-dns")

# フレームワーク/CDNの既定値 → 運営者の癖としては弱い
GENERIC_COOKIES = {
    "phpsessid", "jsessionid", "asp.net_sessionid", "csrftoken", "xsrf-token",
    "__cf_bm", "_cfuvid", "__cfduid", "awsalb", "awsalbcors", "awsalbtg",
    "laravel_session", "connect.sid", "sessionid", "ci_session",
}


def is_versioned(value: str) -> bool:
    """'nginx/1.18.0' のようにバージョンを含む値か。"""
    return "/" in value and any(c.isdigit() for c in value.split("/", 1)[1])


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """指定IPへ接続しつつ、SNIにはドメイン名を載せる。"""

    def __init__(self, host, ip, **kw):
        super().__init__(host, **kw)
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, ip, **kw):
        super().__init__(host, **kw)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class InfraTracker:
    def __init__(self, target_domain, username=None, password=None,
                 recent_days=DEFAULT_RECENT_DAYS, probe=True):
        self.target = target_domain.lower().strip()
        self.recent_days = recent_days
        self.probe = probe
        self.graph = nx.Graph()

        # 認証はpDNS専用セッションにのみ付与する
        self.pdns_session = requests.Session()
        self.pdns_session.headers["User-Agent"] = USER_AGENT
        if username and password:
            self.pdns_session.auth = (username, password)
        self.pdns_available = bool(username and password)

        # crt.sh / ipinfo など認証不要の通信用
        self.plain_session = requests.Session()
        self.plain_session.headers["User-Agent"] = USER_AGENT

        self.ip_info_cache = {}       # ip -> dict | None(取得失敗)
        self.ip_last_seen = {}        # ip -> epoch
        self.header_profiles = {}     # "domain@ip" -> dict
        self._lock = threading.Lock()
        self._warned_pdns = False

    # ---------- IP ユーティリティ ----------
    @staticmethod
    def is_public_ip(value: str) -> bool:
        try:
            return ipaddress.ip_address(value).is_global
        except ValueError:
            return False

    def is_recent(self, ip: str) -> bool:
        seen = self.ip_last_seen.get(ip)
        if seen is None:
            return False
        return (time.time() - seen) <= self.recent_days * 86400

    # ---------- Layer 1: DNS ----------
    def get_pdns(self, indicator: str) -> list:
        if not self.pdns_available:
            return []
        records = []
        try:
            res = self.pdns_session.get(f"{CIRCL_PDNS_URL}{indicator}", timeout=REQUEST_TIMEOUT)
            if res.status_code == 401:
                with self._lock:
                    self.pdns_available = False
                    if not self._warned_pdns:
                        self._warned_pdns = True
                        print("  ⚠️  CIRCL認証エラー: pDNSを無効化し、現在のDNS解決へ切り替える")
                return []
            if res.status_code == 200:
                for line in res.text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except requests.RequestException as e:
            print(f"  ⚠️  pDNS接続エラー ({indicator}): {e}")
        return [r for r in records if r.get("rrtype") in ("A", "AAAA", "CNAME")]

    def live_resolve(self, domain: str) -> dict:
        """pDNSが使えない場合の現在のA/AAAA解決。"""
        out = {}
        try:
            for info in socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP):
                out[info[4][0]] = int(time.time())
        except socket.gaierror:
            pass
        return out

    def resolve_domain_to_ips(self, domain: str) -> dict:
        """ip -> last_seen(epoch)。公開IPのみ返す。CNAMEは1段階追跡。"""
        found = {}

        def absorb(records):
            cnames = set()
            for r in records:
                rtype, rdata = r.get("rrtype"), r.get("rdata", "")
                if rtype in ("A", "AAAA"):
                    if self.is_public_ip(rdata):
                        try:
                            last = int(r.get("time_last") or 0)
                        except (TypeError, ValueError):
                            last = 0
                        found[rdata] = max(found.get(rdata, 0), last)
                elif rtype == "CNAME":
                    cnames.add(rdata.rstrip("."))
            return cnames

        if self.pdns_available:
            cnames = absorb(self.get_pdns(domain))
            for cname in sorted(cnames):
                if cname != domain:
                    absorb(self.get_pdns(cname))
        if not found and not self.pdns_available:
            for ip, ts in self.live_resolve(domain).items():
                if self.is_public_ip(ip):
                    found[ip] = ts
        return found

    # ---------- Layer 2: CT ----------
    @staticmethod
    def get_registered_domain(domain: str) -> str:
        parts = domain.lower().split(".")
        if len(parts) >= 3 and ".".join(parts[-2:]) in PUBLIC_SUFFIX_2:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:]) if len(parts) >= 2 else domain

    def get_ct_logs(self, domain: str) -> list:
        reg = self.get_registered_domain(domain)
        print(f"  📜 [CT] 証明書履歴を調査: {reg}")
        try:
            res = self.plain_session.get(CRT_SH_URL.format(f"%.{reg}"), timeout=30)
            if res.status_code == 200 and "json" in res.headers.get("Content-Type", ""):
                names = set()
                for entry in res.json():
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lower()
                        if (name and not name.startswith("*")
                                and not any(n in name for n in CT_NOISE_SUBSTRINGS)):
                            names.add(name)
                return sorted(names)
            print(f"  ⚠️  CTログが想定外の応答 (status={res.status_code})")
        except (requests.RequestException, ValueError) as e:
            print(f"  ⚠️  CTログ取得エラー: {e}")
        return []

    def pick_ct_domains(self, names: list) -> list:
        """決定論的に選ぶ: 別の登録ドメイン(SAN共有)を優先し、残りをアルファベット順。"""
        own = self.get_registered_domain(self.target)
        others = [n for n in names if n != self.target and self.get_registered_domain(n) != own]
        same = [n for n in names if n != self.target and self.get_registered_domain(n) == own]
        return (others + same)[:MAX_CT_DOMAINS]

    # ---------- Layer 3: HTTP ----------
    def probe_headers(self, domain: str, ip: str) -> dict:
        """ipへ接続し、SNI/Hostにdomainを使う。リダイレクトは追わず、本文は読まない。"""
        empty = {"server": "Unknown", "powered": "Unknown", "cookies": [],
                 "status": 0, "proto": None, "location": None, "host": domain, "ip": ip}
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # 調査用途: 自己署名証明書も観測対象

        for proto in ("https", "http"):
            conn = None
            try:
                if proto == "https":
                    conn = PinnedHTTPSConnection(domain, ip, timeout=PROBE_TIMEOUT, context=ctx)
                else:
                    conn = PinnedHTTPConnection(domain, ip, timeout=PROBE_TIMEOUT)
                conn.request("GET", "/", headers={"Host": domain, "User-Agent": USER_AGENT,
                                                  "Connection": "close"})
                resp = conn.getresponse()
                headers = resp.getheaders()  # 同名ヘッダーも個別に保持される
                cookies = sorted({
                    v.split("=", 1)[0].strip()
                    for k, v in headers if k.lower() == "set-cookie" and "=" in v
                })
                return {
                    "server": resp.getheader("Server") or "Unknown",
                    "powered": resp.getheader("X-Powered-By") or "Unknown",
                    "cookies": cookies,
                    "status": resp.status,
                    "proto": proto,
                    "location": resp.getheader("Location"),
                    "host": domain,
                    "ip": ip,
                }
            except (OSError, http.client.HTTPException, ssl.SSLError):
                continue
            finally:
                if conn is not None:
                    conn.close()
        return empty

    # ---------- ASN ----------
    def fetch_ip_info(self, ip: str):
        """成功: dict、失敗: None(判定不能)。"""
        try:
            res = self.plain_session.get(f"https://ipinfo.io/{ip}/json", timeout=10)
            if res.status_code == 200:
                data = res.json()
                org = (data.get("org") or "").lower()
                data["_is_cloud"] = any(k in org for k in CLOUD_KEYWORDS)
                return data
            if res.status_code == 429:
                print(f"  ⚠️  ipinfo.io レートリミット (IP: {ip}) → 判定不能として扱う")
        except (requests.RequestException, ValueError):
            pass
        return None

    @staticmethod
    def subnet_of(ip: str) -> str:
        addr = ipaddress.ip_address(ip)
        prefix = 24 if addr.version == 4 else 48
        return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))

    # ---------- スコアリング ----------
    def calculate_relevance_score(self, cluster) -> dict:
        domains = sorted(n for n in cluster if self.graph.nodes[n]["type"] == "domain")
        ips = sorted(n for n in cluster if self.graph.nodes[n]["type"] == "ip")
        if len(domains) < 2:
            return {"score": 0, "reasons": []}

        score, reasons = 0, []

        # --- IP/ASN: 取得できたIPだけで判断。判定不能は加点しない ---
        known = {ip: self.ip_info_cache[ip] for ip in ips if self.ip_info_cache.get(ip)}
        if len(known) < len(ips):
            reasons.append(f"ASN情報が未取得のIPが{len(ips) - len(known)}個あり、IP関連の加点は取得済み分のみ")
        non_cloud = [ip for ip, d in known.items() if not d["_is_cloud"]]
        cloud = [ip for ip, d in known.items() if d["_is_cloud"]]
        if non_cloud:
            score += 15
            reasons.append(f"非クラウドIPを共有: {len(non_cloud)}個 (+15)")
        elif cloud:
            score += 3
            reasons.append(f"クラウド/CDN IPのみ(ノイズ注意) (+3)")

        if len(known) >= 2 and len(known) == len(ips):
            if len({self.subnet_of(ip) for ip in known}) == 1:
                score += 8
                reasons.append("全IPが同一サブネット (+8)")
            orgs = {d.get("org") for d in known.values() if d.get("org")}
            if len(orgs) == 1 and len(orgs | {None}) == 2:
                score += 10
                reasons.append(f"全IPが同一ASN/Org: {next(iter(orgs))} (+10)")

        # --- HTTPヘッダー: 異なるドメイン間で比較 ---
        by_domain = {}
        for d in domains:
            for ip in ips:
                p = self.header_profiles.get(f"{d}@{ip}")
                if p and p["status"] > 0:
                    by_domain.setdefault(d, p)
        if len(by_domain) >= 2:
            profiles = list(by_domain.values())

            servers = [p["server"] for p in profiles if p["server"] != "Unknown"]
            if len(servers) >= 2 and len(set(servers)) == 1:
                if is_versioned(servers[0]):
                    score += 15
                    reasons.append(f"Server完全一致(バージョン付き): {servers[0]} (+15)")
                else:
                    score += 3
                    reasons.append(f"Server一致(汎用値): {servers[0]} (+3)")

            cookie_sets = [set(c for c in p["cookies"] if c.lower() not in GENERIC_COOKIES)
                           for p in profiles]
            cookie_sets = [s for s in cookie_sets if s]
            if len(cookie_sets) >= 2:
                common = set.intersection(*cookie_sets)
                if common:
                    score += 30
                    reasons.append(f"固有Cookie名が一致: {', '.join(sorted(common))} (+30)")

            powered = [p["powered"] for p in profiles if p["powered"] != "Unknown"]
            if len(powered) >= 2 and len(set(powered)) == 1 and is_versioned(powered[0]):
                score += 8
                reasons.append(f"X-Powered-By完全一致(バージョン付き): {powered[0]} (+8)")
        else:
            reasons.append(f"ヘッダー比較に使えるドメインが{len(by_domain)}件のみ(比較不可)")

        return {"score": score, "reasons": reasons}

    # ---------- 出力 ----------
    def draw_graph(self, filename="infra_map.png"):
        plt.figure(figsize=(16, 12))
        pos = nx.spring_layout(self.graph, k=0.9, iterations=60, seed=42)
        nodes = list(self.graph.nodes())
        nx.draw(self.graph, pos, nodelist=nodes, with_labels=True,
                node_color=[self.graph.nodes[n]["color"] for n in nodes],
                node_size=1400, font_size=8, font_weight="bold",
                edge_color="gray", linewidths=1.5, alpha=0.95)
        plt.title(f"Infrastructure Map: {self.target}", fontsize=16)
        plt.savefig(filename, dpi=150, bbox_inches="tight")
        plt.close()
        print(f"  ✅ '{filename}' を保存")

    def save_report(self, scored, filename="report.json"):
        report = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "recent_days": self.recent_days,
            "probe_enabled": self.probe,
            "nodes": [{"id": n, **a} for n, a in self.graph.nodes(data=True)],
            "edges": [{"source": u, "target": v} for u, v in self.graph.edges()],
            "ip_info": self.ip_info_cache,
            "ip_last_seen": self.ip_last_seen,
            "header_profiles": self.header_profiles,
            "clusters": [
                {"id": i + 1,
                 "domains": sorted(n for n in c if self.graph.nodes[n]["type"] == "domain"),
                 "ips": sorted(n for n in c if self.graph.nodes[n]["type"] == "ip"),
                 "score": s["score"], "reasons": s["reasons"]}
                for i, c, s in scored
            ],
        }
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"  💾 '{filename}' を保存")

    @staticmethod
    def percentile(values, q):
        s = sorted(values)
        if not s:
            return 0
        k = (len(s) - 1) * q
        lo, hi = int(k), min(int(k) + 1, len(s) - 1)
        return s[lo] + (s[hi] - s[lo]) * (k - lo)

    def display_results(self, scored):
        print("\n" + "=" * 70)
        print(" 分析結果 (Relevance Scoring v1.6)")
        print("=" * 70)
        if not scored:
            print("\n  複数ドメインを含むクラスターは見つからなかった。")
            if not self.pdns_available:
                print("  (pDNS未使用のため、現在のDNS解決のみが材料。CIRCL認証で改善する可能性あり)")
            return

        threshold = max(40, self.percentile([s["score"] for _, _, s in scored], 0.65))
        print(f"\n  動的閾値: {threshold:.1f}点 (上位35%の境界、下限40)\n")
        found = False
        for i, cluster, s in scored:
            domains = sorted(n for n in cluster if self.graph.nodes[n]["type"] == "domain")
            ips = sorted(n for n in cluster if self.graph.nodes[n]["type"] == "ip")
            if s["score"] >= threshold:
                found = True
                print(f"🔥 [高関連度: {s['score']}点] クラスター #{i + 1}")
                print(f"   ドメイン: {', '.join(domains)}")
                print(f"   IP: {', '.join(ips)}")
                for r in s["reasons"]:
                    print(f"   ✔️  {r}")
                print()
            else:
                print(f"🌫️  [低関連度: {s['score']}点] クラスター #{i + 1}: "
                      f"{', '.join(domains[:5])}{'...' if len(domains) > 5 else ''}")
        if not found:
            print("\n  高関連度クラスターなし (CDN/共有ホスティングのノイズが支配的な可能性)")
        print("\n  ※ スコアは手がかりであり、同一運営者の証明ではない。")

    # ---------- メイン ----------
    def build_probe_tasks(self, clusters):
        """各クラスターから『異なるドメイン × 1つの最近の公開IP』を決定論的に選ぶ。"""
        tasks = []
        for cluster in sorted(clusters, key=lambda c: (-len(c), sorted(c)[0])):
            domains = sorted(n for n in cluster if self.graph.nodes[n]["type"] == "domain")
            if len(domains) < 2:
                continue
            picked = 0
            for d in domains:
                if picked >= MAX_DOMAINS_PER_CLUSTER:
                    break
                cand = sorted(ip for ip in self.graph.neighbors(d) if self.is_recent(ip))
                if cand:
                    tasks.append((d, cand[0]))
                    picked += 1
        return tasks[:MAX_HTTP_CHECKS]

    def run_analysis(self):
        print(f"\n追跡開始: {self.target}\n")
        if not self.pdns_available:
            print("  ℹ️  CIRCL認証なし: pDNSは使わず、現在のDNS解決で代替する\n")

        self.graph.add_node(self.target, type="domain", color="lightblue")
        names = self.get_ct_logs(self.target)
        print(f"  [+] CTログから {len(names)} 件の名前\n")
        candidates = [self.target] + self.pick_ct_domains(names)

        def add_result(domain, ips):
            if not ips:
                return
            if domain not in self.graph:
                self.graph.add_node(domain, type="domain", color="pink")
            for ip, seen in ips.items():
                self.graph.add_node(ip, type="ip", color="lightgreen")
                self.graph.add_edge(domain, ip)
                self.ip_last_seen[ip] = max(self.ip_last_seen.get(ip, 0), seen)

        with ThreadPoolExecutor(max_workers=5) as ex:
            futs = {ex.submit(self.resolve_domain_to_ips, d): d for d in candidates}
            results = {}
            for f in as_completed(futs):
                try:
                    results[futs[f]] = f.result()
                except Exception as e:
                    print(f"  ⚠️  {futs[f]}: {e}")
        for d in candidates:  # 決定論的な順で反映
            add_result(d, results.get(d))

        all_ips = sorted(n for n, a in self.graph.nodes(data=True) if a["type"] == "ip")
        print(f"\n  🌍 {len(all_ips)} 個のIPのASN情報を取得")
        with ThreadPoolExecutor(max_workers=2) as ex:
            for ip, info in zip(all_ips, ex.map(self.fetch_ip_info, all_ips)):
                self.ip_info_cache[ip] = info

        clusters = list(nx.connected_components(self.graph))

        if self.probe:
            tasks = self.build_probe_tasks(clusters)
            print(f"\n  🌐 HTTPヘッダー調査: {len(tasks)} 件 (直近{self.recent_days}日内のIPのみ)")
            with ThreadPoolExecutor(max_workers=3) as ex:
                futs = {ex.submit(self.probe_headers, d, ip): (d, ip) for d, ip in tasks}
                for f in as_completed(futs):
                    d, ip = futs[f]
                    try:
                        self.header_profiles[f"{d}@{ip}"] = f.result()
                    except Exception:
                        pass
        else:
            print("\n  --no-probe: 能動的なHTTP接続は行わない")

        scored = []
        for i, c in enumerate(clusters):
            if sum(1 for n in c if self.graph.nodes[n]["type"] == "domain") >= 2:
                scored.append((i, c, self.calculate_relevance_score(c)))

        self.display_results(scored)
        self.draw_graph()
        self.save_report(scored)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Multi-Layer Infra Tracker v1.6")
    ap.add_argument("--domain", required=True, help="調査対象のドメイン")
    ap.add_argument("--user", help="CIRCL pDNS ユーザー名")
    ap.add_argument("--password", help="CIRCL pDNS パスワード")
    ap.add_argument("--recent-days", type=int, default=DEFAULT_RECENT_DAYS,
                    help="能動接続の対象とするIPの最終観測からの日数 (既定: 90)")
    ap.add_argument("--no-probe", action="store_true", help="HTTP接続を行わない(受動情報のみ)")
    args = ap.parse_args()

    InfraTracker(args.domain, args.user, args.password,
                 recent_days=args.recent_days, probe=not args.no_probe).run_analysis()
