# Cloudflareの背後にある防弾ホスティング(BPH)を調べる手順

> **目的**: フィッシング、マルウェア配信、C2などの不正サイトについて、Cloudflareの背後にある「本当のホスティング先」の候補を絞り込み、通報・追跡の手がかりにする。
> **対象読者**: OSINT / 脅威インテリジェンス / 不正対策の担当者、Python と DNS・HTTP の基礎がある人
> **関連ツール**: Multi-Layer Infra Tracker v1.6(pDNS + CT + HTTPヘッダー + ASN)

---

## 0. 先に読む: 倫理と法的な線引き

このチュートリアルは**帰属(誰が・どこで運用しているか)の推定と通報**のためのものです。次のことはしません。

- オリジンサーバーへの負荷試験、DoS、脆弱性スキャン、ログイン試行
- Cloudflare の保護を回避して攻撃する目的での、オリジンIPの利用
- 許可のないポートスキャンや大量アクセス

守ること:

1. **受動情報を先に**使い切る(RDAP、pDNS、CT、スキャンデータベース)。
2. 能動的な接続は、候補IPへの**1リクエスト程度**にとどめる。
3. 調査の日時・手順・取得物を**記録**する(第9章)。
4. 結論は「確定」「可能性が高い」「可能性あり」で分けて書く。
5. 所属組織のポリシーと、自国の法律(不正アクセス禁止法など)を確認する。判断に迷う場合は法務に相談する。

---

## 1. 前提知識

### 1.1 防弾ホスティング(BPH)とは

苦情・削除要請・法執行からの要請に対して、**対応が極端に遅い、または実質的に無視する**ホスティング事業者の通称です。よく見られる特徴は次のとおりです。

| 特徴 | 調査での見え方 |
| :--- | :--- |
| 苦情(abuse)を無視する | abuse窓口が返信しない、同じ不正サイトが長期間残る |
| 事業者や顧客が匿名 | RDAP/WHOISの情報が薄い、連絡先が使い捨て |
| IP空間を転々とする | 短期間でASNやプレフィックスが入れ替わる |
| 不正の集中 | 同じASN/プレフィックスに、複数の不正ドメインが集まる |
| 小規模な事業者を経由した接続 | 上流(アップストリーム)ASが限られている |

「評判の悪いホスティング事業者」と断定するには、複数の独立した根拠が必要です(第7章)。

### 1.2 Cloudflareは何を隠し、何を隠さないか

Cloudflareのプロキシを使うと、訪問者から見える公開DNSのA/AAAAは**Cloudflareのエッジ**になります。本当のサーバー(オリジン)のIPは見えません。

| 隠れる | 隠れない(調査の入り口) |
| :--- | :--- |
| 現在の公開A/AAAAレコードのオリジンIP | ドメインの登録情報(RDAP)、ネームサーバー |
| オリジン側のHTTPヘッダーの一部 | Cloudflare導入前の**過去のDNS履歴**(pDNS) |
| | **証明書透明性ログ**(CT)に残る名前 |
| | Cloudflareを通っていない**別サブドメイン、MX、SPF** |
| | サイトのコンテンツ、favicon、HTMLの特徴 |
| | 同じ運営者の他のドメイン |

結論として、**オリジンIPが見つかることは多いが、確実ではない**ものとして扱います。

---

## 2. 調査の全体像

```
Step 0  Cloudflare背後かどうか確認
Step 1  登録情報・NS(RDAP)
Step 2  過去のDNS(pDNS)でCloudflare導入前のIPを探す
Step 3  CTログで関連ドメイン・証明書を集める
Step 4  スキャンデータで証明書/favicon/HTMLの一致するIPを探す
Step 5  Cloudflareを通っていないサブドメイン・MX・SPFを見る
Step 6  候補IPを最小限の接続で検証する
Step 7  ASN・上流・同居ドメインで帰属と事業者の性質を評価する
Step 8  信頼度を付けて結論を書く
Step 9  通報する
```

---

## 3. Step 0: Cloudflare背後かどうか確認する

次のうち複数が当てはまれば、Cloudflare経由と見てよいでしょう。

- ネームサーバーが `*.ns.cloudflare.com`
- A/AAAAが Cloudflare の公開IP範囲に含まれる
- 応答ヘッダーに `Server: cloudflare` と `CF-RAY` がある

```bash
dig +short NS example.com
dig +short A example.com
curl -sI https://example.com | grep -i -E '^(server|cf-ray)'
```

Cloudflareの公開IP範囲は、Cloudflareが公開している一覧で判定できます。

```python
import ipaddress
import requests

def load_cloudflare_networks():
    nets = []
    for url in ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"):
        text = requests.get(url, timeout=10).text
        nets += [ipaddress.ip_network(line.strip()) for line in text.split() if line.strip()]
    return nets

CF_NETS = load_cloudflare_networks()

def is_cloudflare(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in CF_NETS if net.version == addr.version)
```

以降の調査では、**Cloudflare IPを「オリジン候補」から除外**します。

---

## 4. 受動調査

### 4.1 Step 1: 登録情報とネームサーバー

```bash
# RDAP(WHOISの後継)。公開サービスの bootstrap を使う
curl -s https://rdap.org/domain/example.com | jq '.events, .entities, .nameservers'
```

見るもの:

- **登録日**: 登録直後に不正利用が始まっていないか
- **レジストラ**: abuse窓口の有無
- **ネームサーバー**: Cloudflare以外のNSを併用していないか、過去に別NSを使っていないか

GDPR以降、登録者情報はマスクされていることが多いです。空欄でも調査は失敗ではありません。

### 4.2 Step 2: pDNSでCloudflare導入前の履歴を探す

Cloudflareに移る前、または設定の合間に、オリジンIPが直接見えていた期間があるかもしれません。

- 使えるサービス: CIRCL pDNS(申請制)、SecurityTrails、DNSDB など
- 見るもの: `time_first` / `time_last`、A/AAAAの変遷、CNAMEチェーン

```bash
python tracker_v1.6.py --domain example.com --user CIRCL_USER --password CIRCL_PASS --no-probe
```

注意点:

- **古いIPは今は別人のものかもしれない**。履歴のIPが今も同じ運営者のものとは限りません。
- Cloudflare導入の**直前の期間**のIPと、現在のIPを分けて記録します。
- 非公開IP、パーキングIP(`127.0.0.1` など)は除外します(v1.6は `is_global` で自動除外)。

### 4.3 Step 3: CTログで関連ドメインと証明書を集める

[crt.sh](https://crt.sh) で、`%.example.com` を検索します。

```bash
curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[].name_value' | sort -u
```

見るもの:

- **SAN(1枚の証明書に載る複数ドメイン)**: 同じ証明書に載る**別の登録ドメイン**は、同じ運営者の有力な手がかりです。
- **発行者**: Cloudflareが発行した証明書(Universal SSL)は、オリジンの手がかりになりません。**Let's Encrypt や他のCAが発行した証明書**は、オリジン側にも同じ証明書が載っている可能性があります。
- **発行日の分布**: 運営開始時期や、ドメインの使い回しの時期が分かります。

`sni.cloudflaressl.com` のような共有証明書の名前はノイズなので除外します(v1.6は除外済み)。

### 4.4 Step 4: スキャンデータベースで一致するIPを探す

Censys、Shodan、FOFA など、インターネット全体のスキャン結果を検索できるサービスを使います。**自分でスキャンするのではなく、すでに集められたデータを検索する**のがポイントです。

| 検索の軸 | 内容 |
| :--- | :--- |
| 証明書のSHA-256 | CTで見つけたオリジン側の証明書を持つIPを探す |
| faviconハッシュ | 同じfaviconを返すサーバーを探す |
| HTMLのtitle / 特徴的な文字列 | 同じサイト(キット)を返すサーバーを探す |
| ヘッダーの組み合わせ | バージョン付きServer、固有のCookie名など |

faviconのハッシュ(Shodan形式)は次のように計算できます。公開サイトからfaviconを通常どおり取得するだけです。

```python
import base64
import mmh3
import requests

def favicon_hash(site: str) -> int:
    content = requests.get(f"https://{site}/favicon.ico", timeout=10).content
    return mmh3.hash(base64.encodebytes(content))

print(favicon_hash("example.com"))
# Shodan: http.favicon.hash:<出力値>
```

結果の扱い:

- ヒットしたIPから、**Cloudflare IPを除外**します。
- ヒットが多すぎる場合(共通のキットや汎用ファビコン)は、他の軸と組み合わせて絞ります。
- 1つの軸だけの一致は**弱い根拠**です。

### 4.5 Step 5: Cloudflareを通っていない名前を見る

Cloudflareのプロキシは、**サブドメインごと**にオン/オフを選べます。プロキシしていない名前は、オリジンIPをそのまま返します。

調べる名前の例:

- CTログで見つけたサブドメイン(`mail.`、`ftp.`、`cpanel.`、`direct.`、`dev.` など)
- `MX` レコードの宛先のA
- `TXT` のSPF内の `ip4:` / `ip6:` / `include:`

```bash
dig +short MX example.com
dig +short TXT example.com | grep -i spf
```

これらのIPがCloudflareの範囲外で、本体サイトと同じASNやサブネットに入るなら、有力な候補です。ただし、メール専用の外部サービスのIPは、本体のオリジンとは別物です。

---

## 5. Step 6: 候補IPの検証(能動・最小限)

受動調査で候補が出たら、**候補IPへ最小限の接続**をして、公開サイトと同じものを返すか確かめます。

やり方の要点:

- **SNIとHostヘッダーに対象ドメインを載せたまま**、候補IPに接続する(v1.6の `probe_headers`)。
- リダイレクトは追わず、本文は読まない(ヘッダーとステータスだけ)。
- 1候補につき**1回**。繰り返し・並列アクセスはしない。

```bash
# 動作確認の例(自分の許可範囲で)。SNI/Hostとも対象ドメインのまま、接続先だけを候補IPにする
curl -sI --resolve example.com:443:203.0.113.50 https://example.com/ -k
```

比較する項目:

| 項目 | 一致の意味 |
| :--- | :--- |
| ステータスコードとリダイレクト先 | 同じアプリケーションの可能性 |
| `Server` / `X-Powered-By`(バージョン付き) | 同じ構成 |
| 固有のCookie名(`PHPSESSID` 等の汎用名は除く) | 同じアプリ・同じ設定者 |
| `<title>` やHTMLのハッシュ | 同じコンテンツ |

注意:

- 候補IPが**デフォルトvhost**を返すだけの場合、一致しないのは普通です。不一致は「候補ではない」の証明になりません。
- オリジンが**Cloudflare以外からのアクセスを拒否**している場合もあります。接続できなくても、候補が誤りとは言えません。
- 一致した場合も、第7章の評価と合わせて信頼度を決めます。

---

## 6. Infra Tracker v1.6 での実行例

```bash
pip install requests networkx matplotlib

# 受動情報のみ(推奨の最初の一歩)
python tracker_v1.6.py --domain example.com --user CIRCL_USER --password CIRCL_PASS --no-probe

# 候補IPが固まり、検証の許可がある場合のみ
python tracker_v1.6.py --domain example.com --user CIRCL_USER --password CIRCL_PASS --recent-days 30
```

結果の読み方(Cloudflareの背後にある場合):

- **Cloudflare IPだけで構成されたクラスター**は、+3点にとどまります。同じCDNのIPを共有しているだけなので、運営者の証拠になりません。
- **非Cloudflare IPを含むクラスター**(過去のpDNS、プロキシしていないサブドメイン由来)は、非クラウドIPとして加点されます。ここを重点的に見ます。
- 「ASN情報が未取得」と表示された場合、その分は判断材料から外れています。ipinfo.ioのレート制限が原因の可能性があるので、時間をおいて再実行します。

v1.6単体ではカバーしない項目(手動または拡張で補う):

- スキャンデータベース(Censys/Shodan)での証明書・favicon検索
- MX/SPFの解析
- Cloudflare IP範囲による自動除外(第3章のコードを組み込める)

---

## 7. Step 7: 帰属と「防弾」性の評価

候補IPが得られたら、次の情報を集めます。

| 確認事項 | 方法 |
| :--- | :--- |
| ASNと組織名 | ipinfo.io、bgp.he.net、RIPEstat |
| 上流(アップストリーム)AS | bgp.he.net の Peers、RIPEstat の AS Neighbours |
| 同じASN/プレフィックスの他の不正サイト | URLhaus、abuse.ch、各種ブロックリスト、pDNSの逆引き |
| 事業者の評判 | Spamhaus ASN-DROP、各種のレポート |
| 同居ドメイン | 同一IPの逆引き(pDNS)で、似た目的のドメインが並ぶか |
| abuse窓口の実在 | RDAPの `abuse` 連絡先、過去の通報への反応 |

「防弾ホスティングである」と言うには、次のような**独立した根拠が複数**必要です。

- [ ] ブロックリストに事業者・ASNが載っている
- [ ] 不正サイトが同じプレフィックスに集中している
- [ ] 通報に対する長期の無反応が記録されている
- [ ] 登録情報が不自然に薄い、または偽装されている

1つだけでは「評判が悪い」「小規模」の可能性が残ります。

---

## 8. Step 8: 結論の書き方(信頼度)

| 信頼度 | 目安 |
| :--- | :--- |
| **確定** | 運営者の自白、事業者からの回答、法的手続きでの確認など、外部の確認がある |
| **可能性が高い** | 独立した3つ以上の根拠が一致(例: 過去のpDNS + 証明書一致 + HTTP応答一致) |
| **可能性あり** | 1〜2の根拠のみ。偶然や共有ホスティングの可能性が残る |

主な誤検知の原因:

- 共有ホスティング/リセラーで、無関係なサイトが同じIPにいる
- 古いIPが、今は別の利用者のものになっている
- 汎用のfavicon、フレームワークの既定のCookie、一般的なServer値の一致
- ハニーポットや、わざと似せたサイト

---

## 9. 記録と通報

### 9.1 調査記録のテンプレート

```
調査ID:
調査日時(UTC):
対象ドメイン / URL:
調査者:
Cloudflare経由の確認: (NS / IP範囲 / ヘッダー)
受動調査: (使ったサービス、クエリ、取得日時)
候補IP:
  - IP:
    根拠(独立した根拠の数と内容):
    能動接続: 実施 / 未実施(実施した場合は日時と内容)
    ASN / 組織 / 上流:
信頼度:
未確認の点・誤検知の可能性:
```

スクリーンショット、`report.json`、`infra_map.png` は、取得日時とあわせて保存します。

### 9.2 通報先

| 宛先 | 内容 |
| :--- | :--- |
| **Cloudflareのabuse窓口** | 対象がCloudflareのプロキシを使っている場合の通報。通報は事業者へ転送され、カテゴリによっては報告者にホスティング事業者の情報が開示される運用がある(最新の運用は公式ページで確認する) |
| **ホスティング事業者・ASNのabuse窓口** | RDAPの連絡先宛。候補IPが確からしい場合のみ。無反応の記録も残す |
| **レジストラ** | ドメインのabuse窓口 |
| **上流のISP / トランジット事業者** | 事業者が無反応の場合の次の段階 |
| **JPCERT/CC など** | 国内のインシデント調整機関 |
| **フィッシング対策団体・ブラウザの報告窓口** | APWG、Netcraft、Google Safe Browsing、Microsoftなど |
| **法執行機関** | 被害がある場合、または確度が高い場合。証拠は「手がかり」として渡す |

通報には、**確認できた事実**(いつ・何を観測したか)と、**推測**(信頼度つき)を分けて書きます。

---

## 10. トラブルシューティング

**Q. 履歴を調べてもCloudflare導入前のIPが出ない**
A. 最初からCloudflare経由で公開されたか、使っているpDNSがその期間を観測していない可能性があります。別のpDNSやCTからのサブドメイン調査(4.5)に切り替えます。

**Q. 候補IPが複数出て、どれか決められない**
A. 無理に1つに絞らず、候補を信頼度つきで並べて報告します。

**Q. 候補IPに接続しても、サイトと違うものが返る**
A. デフォルトvhostや、Cloudflare以外を拒否する設定が原因かもしれません。不一致だけで候補を捨てず、受動調査の根拠を重視します。

**Q. スコアが全クラスターで低い**
A. Cloudflare IPだけのクラスターは、設計上低くなります。pDNSの過去IPやCT由来の別の登録ドメインに注目します。

**Q. ipinfoが429を返す**
A. 未認証の利用には制限があります。時間をおくか、APIトークンを使うか、IP数を絞ります。取得できなかったIPは「判定不能」として扱われます。

---

## 11. 参考(サービス名)

- RDAP: rdap.org(各レジストリのbootstrap)
- CT: crt.sh
- pDNS: CIRCL Passive DNS、SecurityTrails、DNSDB
- スキャンデータ: Censys、Shodan、FOFA
- BGP/ASN: bgp.he.net、RIPEstat、ipinfo.io
- ブロックリスト: Spamhaus(DROP / ASN-DROP)、abuse.ch(URLhaus ほか)
- Cloudflare IP範囲: cloudflare.com/ips

利用規約・利用上限・料金は各サービスの最新の案内を確認してください。

---

*本チュートリアルは、防御・調査・通報を目的として作成しています。許可のないシステムへの接続や、保護の回避を目的とした利用はしないでください。*
