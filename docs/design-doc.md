# ctun — Engineering Design Document
**نسخه:** 2.0 (مبتنی بر fork از paqet)  
**تاریخ:** ۱۴۰۴/۰۳/۰۶ (2026-05-27)  
**وضعیت:** پیش‌نویس — استراتژی fork

---

## فهرست مطالب

1. [خلاصه اجرایی](#1-خلاصه-اجرایی)
2. [اهداف و محدودیت‌ها](#2-اهداف-و-محدودیت‌ها)
3. [تصمیم بنیادی: Fork از paqet](#3-تصمیم-بنیادی-fork-از-paqet)
4. [نقشه تغییرات نسبت به paqet](#4-نقشه-تغییرات-نسبت-به-paqet)
5. [معماری نهایی](#5-معماری-نهایی)
6. [لایه‌بندی پروتکل](#6-لایه‌بندی-پروتکل)
7. [Transport Layer — رابط و توسعه‌پذیری](#7-transport-layer)
8. [لایه امنیت — ارتقاء](#8-لایه-امنیت)
9. [لایه اطمینان (KCP)](#9-لایه-اطمینان-kcp)
10. [لایه Multiplexing (smux)](#10-لایه-multiplexing-smux)
11. [SOCKS5 و Proxy Logic](#11-socks5-و-proxy-logic)
12. [مدیریت kernel interference](#12-مدیریت-kernel-interference)
13. [فرمت پکت‌ها](#13-فرمت-پکت‌ها)
14. [CLI و پیکربندی](#14-cli-و-پیکربندی)
15. [ساختار پروژه (پس از fork)](#15-ساختار-پروژه)
16. [وابستگی‌ها](#16-وابستگی‌ها)
17. [GitHub Actions — Build Pipeline](#17-github-actions)
18. [نقشه راه پیاده‌سازی](#18-نقشه-راه-پیاده‌سازی)
19. [ریسک‌ها و چالش‌ها](#19-ریسک‌ها-و-چالش‌ها)

---

## 1. خلاصه اجرایی

`ctun` یک ابزار پروکسی تونل‌ساز است که تمام ترافیک بین کلاینت و سرور را **صرفاً از طریق پکت‌های TCP SYN** با داده‌ی جاسازی‌شده در payload (به سبک TCP Fast Open) انتقال می‌دهد. از دید یک ناظر شبکه، تمام ترافیک این تونل به شکل یک سیل SYN packet دیده می‌شود و هیچ اتصال TCP کامل (SYN-ACK، ACK) وجود ندارد.

**استراتژی توسعه:** ctun به جای بازنویسی از صفر، **fork از پروژه‌ی paqet** ([hanselime/paqet](https://github.com/hanselime/paqet) — MIT License) است. paqet در حال حاضر اکثر زیرساخت مورد نیاز را پیاده کرده (raw TCP injection، KCP، smux، SOCKS5، AEAD encryption، cobra CLI، YAML config، چندسکویی) و یک `local_flag`/`remote_flag` آرایه‌ی قابل پیکربندی دارد که حالت SYN-only را با مقدار `["S"]` پشتیبانی می‌کند. وظیفه‌ی ctun اضافه کردن قطعات گمشده و سفت‌کاری حالت SYN-only است.

**جریان کلی:**

```
User App → SOCKS5 (localhost) → ctun client → [SYN packets] → ctun server → Internet
                                                ←————————————←
                                            (return path هم SYN)
```

---

## 2. اهداف و محدودیت‌ها

### اهداف اصلی

| هدف | توضیح | وضعیت در paqet |
|-----|-------|----------------|
| **SYN-only transport** | تمام ترافیک client↔server فقط از طریق TCP SYN | پشتیبانی پایه (`flag: ["S"]`) — نیاز به سفت‌کاری |
| **TCP Fast Open option** | جاسازی session cookie در TCP Option Kind=34 | ❌ ندارد — باید اضافه شود |
| **Extensible transport** | اضافه کردن transport جدید بدون تغییر کد بالایی | ❌ ندارد — Transport interface باید استخراج شود |
| **رمزنگاری مدرن** | ChaCha20-Poly1305 + HKDF + anti-replay | AES/Salsa موجود؛ ChaCha20 و anti-replay باید اضافه شود |
| **احراز هویت** | HELLO handshake مبتنی بر HMAC | باید اضافه شود |
| **تک باینری** | یک فایل اجرایی با subcommand برای server/client | ✅ از paqet |
| **Cross-platform build** | Linux، macOS، Windows؛ amd64 و arm64 | ✅ از paqet |

### محدودیت‌های طراحی

- نیاز به دسترسی **root** یا `CAP_NET_RAW` (برای raw socket)
- نیاز به تنظیم firewall rule (iptables/pf) برای جلوگیری از پاسخ kernel به SYNها
- **CGO required** — paqet از `gopacket/pcap` (libpcap) استفاده می‌کند، که به libpcap (Linux/macOS) یا Npcap (Windows) وابسته است. ctun این تصمیم را حفظ می‌کند تا چندسکویی بودن paqet را از دست ندهد. (مهاجرت اختیاری به AF_PACKET/BPF بدون CGO در آینده — Phase 5.)

---

## 3. تصمیم بنیادی: Fork از paqet

### 3.1 چرا paqet نقطه‌ی شروع مناسبی است

paqet یک پروکسی packet-level دو طرفه‌ی Go است که با راه‌اندازی `pcap` پکت‌ها را capture و TCP پکت‌های ساخته‌شده را inject می‌کند. این پروژه از قبل دارای موارد زیر است:

| ویژگی | جزئیات در paqet |
|--------|------------------|
| **Raw TCP packet I/O** | `internal/socket/` — `RecvHandle`/`SendHandle` بر اساس `pcap.Handle` با BPF filter |
| **KCP reliability** | `github.com/xtaci/kcp-go/v5` — قابل پیکربندی با preset های `normal/fast/fast2/fast3` |
| **smux multiplexing** | `github.com/xtaci/smux` با تنظیم keepalive و buffer |
| **SOCKS5 server** | `github.com/txthinking/socks5` — همراه با احراز هویت اختیاری |
| **Port forwarding** | جدا از SOCKS5 |
| **AEAD encryption** | AES variants، Salsa20، Blowfish + حالت‌های `none`/`null` |
| **Configurable TCP flags** | `network.tcp.local_flag` و `network.tcp.remote_flag` آرایه‌ای از ترکیب فلگ‌ها (`["S"]`, `["A"]`, `["PA"]`, ...) — cycle می‌شوند برای تنوع pattern |
| **iptables integration** | دستور `iptables -t raw -A PREROUTING -p tcp --dport <PORT> -j NOTRACK` (مستندسازی شده) |
| **Cross-platform** | Linux، macOS، Windows |
| **cobra CLI + YAML config** | `cmd/` و `internal/conf/` |
| **Diagnostics** | subcommandهای `ping`، `dump`، `secret` |
| **MIT License** | fork-friendly |

### 3.2 شکاف‌های paqet نسبت به اهداف ctun

| شکاف | تأثیر | تخمین زمان |
|------|--------|-------------|
| TFO Option (Kind=34) با cookie ۸ بایتی در TCP header وجود ندارد | بدون این، پکت‌های ما به جای SYN معتبر TFO، فقط "SYN با payload" دیده می‌شوند | کم — یک TCPOption اضافه در craft.go |
| ChaCha20-Poly1305 پشتیبانی نمی‌شود | امنیت مدرن (constant-time، side-channel resistant) | متوسط — اضافه به enum encryption |
| HKDF-SHA256 key derivation وجود ندارد | کلیدهای enc/auth جدا از یک PSK | کم |
| Anti-replay sliding window 64-bit وجود ندارد | امکان حمله‌ی replay | متوسط — لایه جدید بین encryption و KCP |
| HELLO/HELLO_ACK handshake وجود ندارد | سرور هر packet را decode می‌کند، حتی از مهاجم | متوسط — session manager جدید |
| Transport interface قابل توسعه به صورت formal نیست | اضافه کردن SYN-ACK/UDP/ICMP در آینده سخت می‌شود | متوسط — refactor `internal/socket/` |
| Wire format از `encoding/gob` استفاده می‌کند | overhead زیاد، نسخه‌بندی ضعیف، fingerprint قابل شناسایی | متوسط — جایگزینی با binary فرمت ثابت |

### 3.3 مقایسه‌ی هزینه: fork vs from-scratch

| معیار | Fork از paqet | بازنویسی از صفر |
|--------|---------------|------------------|
| زمان تا MVP | ~۲ هفته (فقط شکاف‌ها) | ~۸ هفته (همه چیز) |
| ریسک bug در لایه‌های پایه (raw socket، KCP، smux) | کم — تست‌شده در paqet | بالا |
| سازگاری چندسکویی | از paqet می‌گیریم (Linux/macOS/Windows) | باید جداگانه پیاده شود |
| تطابق دقیق با design اولیه | ~۸۰٪ — برخی انتخاب‌ها (pcap/CGO، gob) از paqet به ارث می‌رسند | ۱۰۰٪ |
| Upstream merge ها (در صورت توسعه‌ی paqet) | ممکن | غیرممکن |

**نتیجه:** Fork. تطابق ۸۰٪ کافی است و شکاف‌های ۲۰٪ بقیه به صورت surgical روی کد کارای paqet اضافه می‌شوند، نه بازنویسی از صفر یک پروژه‌ی شبکه‌ای پیچیده.

### 3.4 تصمیم در مورد CGO

paqet از `gopacket/pcap` استفاده می‌کند که به libpcap وابسته است → **CGO_ENABLED=1**. این برخلاف هدف اولیه‌ی design doc v1.0 بود. تصمیم نهایی:

- **Phase 1–4:** CGO و libpcap را می‌پذیریم. مزیتش: چندسکویی شامل Windows، کد paqet دست‌نخورده باقی می‌ماند.
- **Phase 5 (اختیاری):** اضافه کردن backend `AF_PACKET` (Linux) و `/dev/bpf` (macOS) به صورت build tag (`//go:build !pcap`). انتخاب در زمان compile بین pure-Go و pcap.

---

## 4. نقشه تغییرات نسبت به paqet

این جدول مرجع اصلی توسعه‌دهنده است: هر شکاف ctun، فایلِ هدف و نوع تغییر را مشخص می‌کند.

| # | تغییر | فایل‌های paqet | نوع |
|---|-------|----------------|------|
| 1 | اضافه کردن TFO TCPOption (Kind=34، ۸ بایت cookie) به TCP layer | `internal/socket/send_handle.go` | افزودن |
| 2 | فیلتر دریافت: فقط SYN با TFO option معتبر | `internal/socket/recv_handle.go` | تغییر |
| 3 | استخراج `Transport` interface formal + registry | `internal/socket/` → جدید `internal/transport/` | refactor |
| 4 | افزودن ChaCha20-Poly1305 به enum encryption | `internal/protocol/` یا cipher registry موجود | افزودن |
| 5 | HKDF-SHA256 برای derive کلیدهای `enc`/`auth` از PSK | جدید: `internal/crypto/keyderive.go` | افزودن |
| 6 | Anti-replay sliding window | جدید: `internal/crypto/antireplay.go` | افزودن |
| 7 | HELLO/HELLO_ACK handshake با HMAC | جدید: `internal/session/handshake.go` | افزودن |
| 8 | جایگزینی wire format (از `gob` به binary ثابت) | `internal/protocol/protocol.go` | بازنویسی |
| 9 | Firewall rule manager خودکار (apply + cleanup با signal handler) | جدید: `internal/firewall/` (Linux + Darwin + Windows) | افزودن |
| 10 | تغییر نام binary به `ctun`، module path به `ctun` | `go.mod`، `cmd/` | rename |
| 11 | اضافه کردن zero-config preset `--transport syn` (با همه‌ی پیش‌فرض‌های لازم) | `cmd/client.go`, `cmd/server.go` | افزودن |
| 12 | (اختیاری Phase 5) Backend `AF_PACKET`/`BPF` بدون CGO | `internal/transport/synraw/` | افزودن build-tagged |

تغییرات paqet که **نگه می‌داریم بدون اصلاح**:

- `internal/socket/recv_handle.go`، `send_handle.go` — منطق pcap (به جز موارد بالا)
- `internal/conf/` — saa ssasaختار YAML config
- `internal/forward/` — منطق KCP↔smux  
- `internal/socks/` — wrapper روی `txthinking/socks5`
- `internal/tnet/` — abstract شبکه و آدرس
- `internal/flog/` — logging
- `cmd/ping.go`, `cmd/dump.go`, `cmd/secret.go` — utility ها
- ساختار build و CI

---

## 5. معماری نهایی

### نمودار component

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLIENT SIDE                              │
│                                                                  │
│  User App ──→ SOCKS5 Server (localhost:1080)   [paqet موجود]    │
│                     │                                            │
│              smux Session (multiplexer)        [paqet موجود]    │
│                     │                                            │
│              KCP Reliable Transport            [paqet موجود]    │
│                     │                                            │
│              ┌──────▼──────────────────────────┐                │
│              │  Security Layer  [ctun جدید]   │                │
│              │    HKDF → enc/auth keys         │                │
│              │    ChaCha20-Poly1305 AEAD       │                │
│              │    Anti-replay 64-bit window    │                │
│              │    HELLO/HELLO_ACK handshake    │                │
│              └──────┬──────────────────────────┘                │
│                     │                                            │
│         ┌───────────▼───────────┐                               │
│         │ Transport Interface   │  [ctun: extract from paqet]   │
│         │ ┌────────────────────┐│                               │
│         │ │ SYN-TFO Transport  ││ ← v1.0 (paqet + TFO option)  │
│         │ │ (TCP SYN + Kind=34)││                               │
│         │ └────────────────────┘│                               │
│         │ ┌────────────────────┐│                               │
│         │ │ SYN-ACK Transport  ││ ← آینده                      │
│         │ └────────────────────┘│                               │
│         │ ┌────────────────────┐│                               │
│         │ │ UDP Transport      ││ ← آینده                      │
│         │ └────────────────────┘│                               │
│         └───────────┬───────────┘                               │
│                     │                                            │
│              pcap.Handle (paqet)                                 │
│              یا AF_PACKET/BPF (Phase 5)                          │
│                     │                                            │
│              iptables/pf rules  [ctun: خودکار]                  │
└─────────────────────│───────────────────────────────────────────┘
                       │
                  [SYN packets only]
                  [TFO cookie + encrypted payload]
                       │
┌─────────────────────│───────────────────────────────────────────┐
│                     │          SERVER SIDE                       │
│                  (آینه‌ی client side)                            │
│                                                                  │
│              iptables/pf DROP (SYN-ACK prevention)               │
│                     │                                            │
│              pcap.Handle + BPF filter                            │
│                     │                                            │
│              SYN-TFO Transport                                   │
│                     │                                            │
│              Security Layer (decrypt + replay check)             │
│                     │                                            │
│              KCP → smux → SOCKS5 protocol dispatcher             │
│                     │                                            │
│              Proxy Handler (Dial به اینترنت آزاد)               │
└─────────────────────────────────────────────────────────────────┘
```

---

## 6. لایه‌بندی پروتکل

```
┌──────────────────────────────────────────┐  Layer 5
│  Application Layer                        │  [paqet]
│  - SOCKS5 (client)                        │
│  - TCP Proxy to Internet (server)         │
└───────────────────┬──────────────────────┘
                    │
┌───────────────────▼──────────────────────┐  Layer 4
│  Multiplexing Layer                       │  [paqet]
│  - smux (xtaci/smux)                      │
└───────────────────┬──────────────────────┘
                    │
┌───────────────────▼──────────────────────┐  Layer 3
│  Reliability Layer                        │  [paqet]
│  - KCP (xtaci/kcp-go/v5)                  │
└───────────────────┬──────────────────────┘
                    │
┌───────────────────▼──────────────────────┐  Layer 2.5  ← جای جدید
│  Security Layer                           │  [ctun جدید]
│  - HKDF-SHA256 key derivation             │
│  - ChaCha20-Poly1305 AEAD                 │
│  - Anti-replay sliding window (64-bit)    │
│  - HELLO/HELLO_ACK handshake              │
└───────────────────┬──────────────────────┘
                    │
┌───────────────────▼──────────────────────┐  Layer 2
│  Transport Layer (extensible interface)  │  [ctun: extract]
│  ┌─────────────────────────────────────┐ │
│  │ SYN-TFO Transport                   │ │ ← v1.0
│  ├─────────────────────────────────────┤ │
│  │ SYNACKTransport (آینده)             │ │
│  ├─────────────────────────────────────┤ │
│  │ UDPTransport (آینده)                │ │
│  └─────────────────────────────────────┘ │
└───────────────────┬──────────────────────┘
                    │
┌───────────────────▼──────────────────────┐  Layer 1
│  Packet I/O Layer                         │  [paqet]
│  - gopacket/pcap (libpcap)                │
│  - cross-platform: Linux/macOS/Windows    │
│  - Phase 5: AF_PACKET/BPF (no CGO)        │
└──────────────────────────────────────────┘
```

**نکته:** ترتیب لایه‌ها در paqet کنونی: `smux → KCP → encryption → packet`. در ctun لایه‌ی security بین KCP و transport می‌نشیند (encryption روی KCP segments) تا anti-replay و HELLO هم پوشش داده شوند. این یک تغییر معماری مهم است.

---

## 7. Transport Layer

### 7.1 رابط (Interface) — جدید در ctun

paqet کنونی ساختار `PacketConn` دارد که هم send و هم recv را قاطی می‌کند. ctun یک interface رسمی استخراج می‌کند تا transport های آینده drop-in باشند:

```go
// internal/transport/transport.go

// Datagram یک واحد داده قابل ارسال/دریافت است
type Datagram struct {
    Data    []byte
    SrcAddr netip.AddrPort
    DstAddr netip.AddrPort
}

// Transport رابط اصلی است که هر transport باید پیاده‌سازی کند
type Transport interface {
    Send(ctx context.Context, d *Datagram) error
    Recv(ctx context.Context) (*Datagram, error)
    LocalAddr() netip.AddrPort
    Close() error
}

type Factory func(cfg Config) (Transport, error)

type Config struct {
    Interface   string
    LocalAddr   netip.AddrPort
    RemoteAddr  netip.AddrPort
    MTU         int
    ExtraParams map[string]any
}

var registry = map[string]Factory{}

func Register(name string, f Factory) { registry[name] = f }

func New(name string, cfg Config) (Transport, error) {
    f, ok := registry[name]
    if !ok { return nil, fmt.Errorf("unknown transport: %s", name) }
    return f(cfg)
}
```

### 7.2 SYN-TFO Transport — پیاده‌سازی پیش‌فرض

پایه: `internal/socket/send_handle.go` و `recv_handle.go` از paqet. تغییرات اضافی:

#### مفهوم TCP Fast Open در ctun

paqet هم‌اکنون داده را در TCP payload می‌گذارد، اما هیچ TFO option در header نمی‌گذارد. این موضوع باعث می‌شود از نظر middlebox ها، SYN با payload "غیر استاندارد" دیده شود. در ctun اضافه می‌کنیم:

```
TCP SYN Packet Structure (ctun):
┌────────────────────────────────────────────────────┐
│  IP Header (20 bytes)             [paqet موجود]    │
├────────────────────────────────────────────────────┤
│  TCP Header (20 bytes)            [paqet موجود]    │
│    - SYN flag = 1                                   │
│    - Seq = random per-packet                        │
│    - Src Port = ephemeral                           │
├────────────────────────────────────────────────────┤
│  TCP Options                                        │
│    - MSS Option (paqet موجود)                       │
│    - TFO Option (Kind=34) ← ctun جدید              │
│      [Kind:1][Len:10][Cookie:8]                    │
│      Cookie = HMAC-SHA256(authKey, sessionID)[:8]  │
├────────────────────────────────────────────────────┤
│  TCP Payload  (تا ~1357 bytes)    [paqet موجود]    │
│    ← اینجا ciphertext ctun قرار می‌گیرد            │
└────────────────────────────────────────────────────┘
```

#### تغییر در `send_handle.go`

اضافه کردن یک TCPOption به layer:

```go
tcpLayer.Options = append(tcpLayer.Options, layers.TCPOption{
    OptionType:   34, // TFO Kind
    OptionLength: 10,
    OptionData:   sessionCookie, // 8 bytes
})
```

#### تغییر در `recv_handle.go`

BPF filter موجود ("only SYN to our port") را نگه می‌داریم. در application layer فیلتر دوم اضافه می‌شود: فقط پکت‌هایی که TFO option دارند و cookie آن‌ها معتبر است (HMAC چک می‌شود).

### 7.3 اضافه کردن Transport جدید در آینده

```go
// internal/transport/synack/synack.go  (مثال آینده)
package synack

func init() { transport.Register("syn-ack", New) }
func New(cfg transport.Config) (transport.Transport, error) { ... }
```

فقط یک فایل جدید + یک `import _ "ctun/internal/transport/synack"` در `cmd/`.

---

## 8. لایه امنیت

### 8.1 Key Derivation — جدید

```go
// internal/crypto/keyderive.go

func DeriveKeys(psk []byte) (encKey, authKey [32]byte) {
    hkdf := hkdf.New(sha256.New, psk, salt, []byte("ctun-v1"))
    io.ReadFull(hkdf, encKey[:])
    io.ReadFull(hkdf, authKey[:])
    return
}
```

- `encKey` → ChaCha20-Poly1305 encryption
- `authKey` → HMAC-SHA256 برای handshake و TFO cookie

`salt` یک ثابت پروژه است (مثلاً 16 بایت hardcoded).

### 8.2 Packet Encryption — جدید

paqet در حال حاضر AES/Salsa/Blowfish دارد. در ctun یک کلید جدید `chacha20poly1305` به enum cipher اضافه می‌کنیم:

```
Encrypted Packet Format:
┌────────────────────────────────────────────────────┐
│  Nonce (12 bytes) — تصادفی per-packet              │
├────────────────────────────────────────────────────┤
│  Ciphertext = ChaCha20-Poly1305.Seal(plaintext)    │
├────────────────────────────────────────────────────┤
│  Auth Tag (16 bytes) — از AEAD                     │
└────────────────────────────────────────────────────┘

Overhead per packet: 28 bytes
```

### 8.3 Anti-Replay — جدید

```go
// internal/crypto/antireplay.go

type ReplayFilter struct {
    window uint64
    maxSeq uint64
    mu     sync.Mutex
}

func (f *ReplayFilter) Check(seq uint64) bool {
    f.mu.Lock()
    defer f.mu.Unlock()
    if seq > f.maxSeq {
        shift := seq - f.maxSeq
        if shift >= 64 { f.window = 0 } else { f.window <<= shift }
        f.maxSeq = seq
        f.window |= 1
        return true
    }
    diff := f.maxSeq - seq
    if diff >= 64 { return false }
    if f.window & (1 << diff) != 0 { return false }
    f.window |= 1 << diff
    return true
}
```

هر پکت یک sequence number یکتا و monotonic در plaintext header دارد (بعد از decrypt چک می‌شود).

### 8.4 Session Handshake — جدید

```
Client → Server:
  SYN[TFO cookie=zeros][payload = HELLO{version, timestamp, HMAC(authKey, "hello"+timestamp)}]

Server → Client (اگر HMAC معتبر):
  SYN[TFO cookie=session_token][payload = HELLO_ACK{session_id, HMAC(authKey, session_id)}]

Server → Client (اگر HMAC نامعتبر):
  هیچ پاسخی نمی‌دهد (silent drop) → سرور invisible باقی می‌ماند
```

پس از handshake، TFO cookie هر پکت برابر `HMAC(authKey, session_id)[:8]` است؛ سرور با چک سریع cookie می‌تواند پکت‌های مهاجم را قبل از decrypt دور بریزد.

---

## 9. لایه اطمینان (KCP)

**از paqet به ارث می‌رسد بدون تغییر.** پارامترهای پیشنهادی پیش‌فرض ctun:

```yaml
kcp:
  mode: fast              # nodelay=1, interval=10, resend=2, nc=1
  mtu: 1350               # محافظه‌کارانه برای path MTU
  window_size: [1024, 1024]
  sndwnd: 1024
  rcvwnd: 1024
```

paqet preset های `normal/fast/fast2/fast3` را همین الان پشتیبانی می‌کند.

---

## 10. لایه Multiplexing (smux)

**از paqet به ارث می‌رسد بدون تغییر.** هر اتصال SOCKS5 → یک `smux.Stream` جدید روی session واحد KCP.

```
smux Session (یک KCP "connection")
 ├── Stream #1  ← TCP connection کاربر ۱
 ├── Stream #2  ← TCP connection کاربر ۲
 └── ...
```

---

## 11. SOCKS5 و Proxy Logic

**از paqet به ارث می‌رسد بدون تغییر.** paqet از `txthinking/socks5` استفاده می‌کند که SOCKS5 (با احراز هویت اختیاری) و forwarding را پیاده کرده. حتی `internal/forward/` paqet به ما port-forwarding مستقل از SOCKS5 می‌دهد.

---

## 12. مدیریت kernel interference

### مشکل

وقتی یک SYN packet به سرور می‌رسد:
- اگر چیزی روی آن پورت listen کند → kernel جواب SYN-ACK می‌دهد
- اگر نه → kernel جواب RST می‌دهد

وقتی یک SYN packet از سرور به کلاینت می‌رسد → kernel کلاینت RST می‌فرستد.

### راه‌حل paqet (موجود)

paqet در README خود این دستور را مستند می‌کند:

```bash
sudo iptables -t raw -A PREROUTING -p tcp --dport <PORT> -j NOTRACK
```

اما این **دستی** است؛ کاربر باید خودش اجرا کند.

### راه‌حل ctun: خودکار + cleanup

ctun موقع start، rule ها را خودش apply می‌کند و موقع shutdown (signal handler) پاک می‌کند:

```go
// internal/firewall/firewall.go

type Manager interface {
    Apply(localPort uint16, isServer bool) error
    Cleanup() error
}
```

#### Linux (iptables)

```go
// internal/firewall/linux.go

func (m *iptablesManager) Apply(port uint16, isServer bool) error {
    rules := []string{
        // NOTRACK مانند paqet
        fmt.Sprintf("-t raw -A PREROUTING -p tcp --dport %d -j NOTRACK", port),
        // DROP پاسخ kernel برای جلوگیری از RST/SYN-ACK
        fmt.Sprintf("-A INPUT -p tcp --dport %d --syn -j DROP", port),
    }
    for _, r := range rules { ... }
    m.applied = rules
    return nil
}

func (m *iptablesManager) Cleanup() error {
    for _, r := range m.applied {
        // همان rule را با -D
        ...
    }
}
```

#### macOS (pf)

```go
// internal/firewall/darwin.go

func (m *pfManager) Apply(port uint16, isServer bool) error {
    rule := fmt.Sprintf("block in proto tcp from any port %d flags S/S\n", port)
    // append to /etc/pf.conf + pfctl -f
    ...
}
```

#### Windows

Windows از NETSH advfirewall استفاده می‌کند:

```go
// internal/firewall/windows.go
func (m *netshManager) Apply(port uint16, isServer bool) error {
    cmd := fmt.Sprintf(`netsh advfirewall firewall add rule name="ctun-%d" dir=in action=block protocol=TCP localport=%d`, port, port)
    ...
}
```

`Cleanup()` به signal handler `SIGINT`/`SIGTERM` متصل می‌شود تا حتی در crash، rule ها لیک نشوند (defer + recover).

---

## 13. فرمت پکت‌ها

### 13.1 Wire Format — جایگزین `gob` paqet

paqet کنونی از `encoding/gob` استفاده می‌کند (نگاه کنید به `internal/protocol/protocol.go`). gob سربار زیاد دارد و قابل تشخیص است. ctun فرمت binary fix-layout را پیاده می‌کند:

```
Plaintext (قبل از encryption):
┌─────────────────────────────────────────────────────┐
│  [Session ID    : 4 bytes]                          │
│  [Sequence      : 8 bytes] (anti-replay)            │
│  [Flags         : 1 byte ]                          │
│       bit 0: HELLO                                  │
│       bit 1: HELLO_ACK                              │
│       bit 2: DATA                                   │
│       bit 3: KEEPALIVE                              │
│       bit 4: CLOSE                                  │
│  [Length        : 2 bytes] (payload length, BE)     │
│  [Payload       : N bytes] (KCP segment یا control) │
└─────────────────────────────────────────────────────┘

Plaintext header overhead: 15 bytes

Encrypted on wire (روی TCP payload):
┌─────────────────────────────────────────────────────┐
│  [Nonce         : 12 bytes]                         │
│  [Ciphertext + Auth Tag from AEAD]                  │
└─────────────────────────────────────────────────────┘

Total overhead per SYN: 12 (nonce) + 15 (header) + 16 (tag) = 43 bytes
Maximum payload per SYN: ~1357 bytes (با MTU=1500)
```

### 13.2 TFO Option در TCP Header

```
TCP Option Kind=34 (Fast Open):
┌──────┬────────┬────────────────────┐
│ Kind │ Length │ Cookie (8 bytes)   │
│  1B  │   1B   │  Session Token     │
└──────┴────────┴────────────────────┘

Session Token = HMAC-SHA256(authKey, sessionID)[0:8]
```

---

## 14. CLI و پیکربندی

### 14.1 نحوه استفاده

ctun ساختار subcommand paqet را حفظ می‌کند:

```bash
# سرور
sudo ctun server --config /etc/ctun/server.yaml

# کلاینت
sudo ctun client --config /etc/ctun/client.yaml

# تولید کلید (از paqet)
ctun secret

# diagnostic ها (از paqet)
ctun ping --config client.yaml
ctun dump --iface eth0 --port 8080

# نمایش transports موجود (ctun جدید)
ctun transports
```

### 14.2 Config File (سازگار با paqet، با اضافات ctun)

```yaml
# /etc/ctun/server.yaml
role: server
log_level: info

network:
  iface: eth0
  ipv4:
    addr: 0.0.0.0
    router_mac: "aa:bb:cc:dd:ee:ff"
  tcp:
    local_flag:  ["S"]      # ← ctun: SYN-only
    remote_flag: ["S"]

server:
  listen: 0.0.0.0:8080
  transport: syn-tfo        # ← ctun: انتخاب transport
  cipher: chacha20poly1305  # ← ctun: cipher جدید
  key: "my-secret-preshared-key"

  firewall:
    auto: true              # ← ctun: مدیریت خودکار iptables/pf
    backend: iptables       # auto | iptables | pf | netsh

kcp:
  mode: fast
  mtu: 1350

smux:
  keepalive_interval: 15s
  keepalive_timeout:  30s
```

### 14.3 ساختار CLI

از paqet به ارث می‌رسد:

```go
// cmd/root.go        — cobra root
// cmd/client.go      — paqet موجود (با اضافات ctun: --transport)
// cmd/server.go      — paqet موجود
// cmd/transports.go  — ctun جدید
```

---

## 15. ساختار پروژه

ساختار paqet را حفظ می‌کنیم و فقط چیزهای جدید اضافه می‌کنیم:

```
ctun/  (fork از paqet)
├── cmd/                       [paqet موجود + اضافات ctun]
│   ├── root.go
│   ├── server.go
│   ├── client.go
│   ├── ping.go               (paqet)
│   ├── dump.go               (paqet)
│   ├── secret.go             (paqet)
│   └── transports.go         (ctun جدید)
│
├── internal/
│   ├── conf/                 [paqet — اضافه کردن فیلدهای transport/cipher/firewall]
│   ├── flog/                 [paqet]
│   ├── socks/                [paqet]
│   ├── tnet/                 [paqet]
│   ├── forward/              [paqet]
│   ├── client/               [paqet]
│   ├── server/               [paqet]
│   ├── pkg/                  [paqet]
│   │
│   ├── socket/               [paqet — تغییر برای TFO option]
│   │   ├── socket.go
│   │   ├── handle.go
│   │   ├── recv_handle.go    ← فیلتر TFO اضافه شود
│   │   └── send_handle.go    ← TFO option اضافه شود
│   │
│   ├── protocol/             [paqet — بازنویسی wire format]
│   │   └── protocol.go       ← gob حذف، binary layout جدید
│   │
│   ├── transport/            [ctun جدید — extract از socket/]
│   │   ├── transport.go      ← interface + registry
│   │   └── syntfo/
│   │       ├── transport.go
│   │       ├── craft.go
│   │       └── filter.go
│   │
│   ├── crypto/               [ctun جدید]
│   │   ├── keyderive.go      ← HKDF
│   │   ├── aead.go           ← ChaCha20-Poly1305 wrapper
│   │   └── antireplay.go     ← sliding window
│   │
│   ├── session/              [ctun جدید]
│   │   ├── handshake.go      ← HELLO/HELLO_ACK
│   │   └── manager.go        ← session lifecycle + TFO cookie
│   │
│   └── firewall/             [ctun جدید]
│       ├── firewall.go       ← interface
│       ├── linux.go          ← iptables (apply + cleanup)
│       ├── darwin.go         ← pf
│       └── windows.go        ← netsh
│
├── example/                  [paqet موجود + نمونه‌های ctun]
│   ├── client.yaml.example
│   └── server.yaml.example
│
├── main.go                   [paqet]
├── go.mod                    [paqet — module path → ctun]
├── go.sum
└── .github/workflows/        [paqet موجود — تنظیم برای ctun release]
```

---

## 16. وابستگی‌ها

از `go.mod` فعلی paqet:

| پکت | نسخه | کاربرد | منشأ |
|-----|-------|---------|------|
| `github.com/gopacket/gopacket` | v1.5.0 | packet crafting/parsing + pcap binding | paqet |
| `github.com/xtaci/kcp-go/v5` | v5.6.64 | KCP reliable transport | paqet |
| `github.com/xtaci/smux` | v1.5.53 | stream multiplexing | paqet |
| `github.com/txthinking/socks5` | latest | SOCKS5 server | paqet |
| `github.com/goccy/go-yaml` | v1.19.2 | YAML config | paqet |
| `github.com/spf13/cobra` | v1.10.2 | CLI | paqet |
| `golang.org/x/crypto` | v0.50.0 | ChaCha20-Poly1305، HKDF، HMAC | paqet (موجود برای cipher دیگر) |
| `golang.org/x/net` | v0.52.0 | BPF utilities | paqet |
| `golang.org/x/sys` | v0.43.0 | syscalls | paqet |

**ctun هیچ dependency جدیدی اضافه نمی‌کند.** همه‌ی نیازهای کریپتو در `golang.org/x/crypto` که paqet از قبل دارد موجود است.

**CGO:** بله — `gopacket/pcap` به libpcap (Linux/macOS) یا Npcap (Windows) نیاز دارد. این هزینه‌ی fork است. (مهاجرت اختیاری Phase 5 برای بدون CGO.)

---

## 17. GitHub Actions

paqet در حال حاضر workflow build دارد در `.github/workflows/`. ctun این workflow را adapt می‌کند:

### 17.1 Build Matrix

```yaml
name: Build ctun

on:
  push:
    tags: ['v*']
  pull_request:

jobs:
  build:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        include:
          # Linux — libpcap-dev از apt
          - os: ubuntu-latest
            goos: linux
            goarch: amd64
            setup: sudo apt-get install -y libpcap-dev
          - os: ubuntu-latest
            goos: linux
            goarch: arm64
            setup: |
              sudo apt-get install -y gcc-aarch64-linux-gnu libpcap-dev:arm64
            cc: aarch64-linux-gnu-gcc
          # macOS — libpcap از قبل موجود
          - os: macos-latest
            goos: darwin
            goarch: amd64
          - os: macos-latest
            goos: darwin
            goarch: arm64
          # Windows — npcap SDK
          - os: windows-latest
            goos: windows
            goarch: amd64

    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - name: Install deps
        if: matrix.setup != ''
        run: ${{ matrix.setup }}
      - name: Build
        env:
          GOOS: ${{ matrix.goos }}
          GOARCH: ${{ matrix.goarch }}
          CC: ${{ matrix.cc }}
          CGO_ENABLED: 1
        run: |
          go build \
            -ldflags="-s -w -X main.version=${{ github.ref_name }}" \
            -trimpath \
            -o "dist/ctun_${{ matrix.goos }}_${{ matrix.goarch }}" \
            ./
      - uses: actions/upload-artifact@v4
        with:
          name: ctun_${{ matrix.goos }}_${{ matrix.goarch }}
          path: dist/

  release:
    needs: build
    if: startsWith(github.ref, 'refs/tags/')
    runs-on: ubuntu-latest
    permissions: { contents: write }
    steps:
      - uses: actions/download-artifact@v4
        with: { path: dist/, merge-multiple: true }
      - run: sha256sum dist/* > dist/SHA256SUMS
      - uses: softprops/action-gh-release@v2
        with: { files: dist/*, generate_release_notes: true }
```

### 17.2 Test + Lint

```yaml
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: sudo apt-get install -y libpcap-dev
      - uses: actions/setup-go@v5
        with: { go-version: '1.22' }
      - run: go test ./... -v -race -timeout 60s
      - uses: golangci/golangci-lint-action@v6
```

---

## 18. نقشه راه پیاده‌سازی

### Phase 0 — Fork و آماده‌سازی (Sprint 0، ~۲ روز)

- [ ] Fork repo `hanselime/paqet` → `<owner>/ctun`
- [ ] تغییر module path: `paqet` → `ctun` در `go.mod` و همه‌ی import ها
- [ ] تغییر binary name در `Makefile` و workflow
- [ ] تست build روی Linux/macOS برای اطمینان از سالم بودن fork
- [ ] تست end-to-end paqet (با `local_flag: ["PA"]`) → اطمینان از کارکرد پایه
- [ ] تست با `local_flag: ["S"]` → بررسی SYN-only feasibility در paqet موجود

### Phase 1 — Transport interface + TFO option (Sprint 1، ~۱ هفته)

- [ ] استخراج `internal/transport/transport.go` با interface و registry
- [ ] تبدیل `internal/socket/` به یک transport به نام `syn-tfo`
- [ ] اضافه کردن TCPOption Kind=34 با 8-byte cookie در `send_handle.go`
- [ ] فیلتر TFO option در `recv_handle.go`
- [ ] subcommand `ctun transports` برای لیست
- [ ] config field `server.transport` و `client.transport`
- [ ] Unit test برای packet crafting (با cookie معتبر و نامعتبر)

### Phase 2 — لایه‌ی security جدید (Sprint 2، ~۱ هفته)

- [ ] `internal/crypto/keyderive.go` — HKDF-SHA256
- [ ] `internal/crypto/aead.go` — ChaCha20-Poly1305 wrapper
- [ ] `internal/crypto/antireplay.go` — sliding window
- [ ] ثبت `chacha20poly1305` در enum cipher موجود paqet
- [ ] Unit test برای anti-replay edge case ها

### Phase 3 — Handshake + wire format جدید (Sprint 3، ~۱ هفته)

- [ ] `internal/session/handshake.go` — HELLO/HELLO_ACK با HMAC
- [ ] `internal/session/manager.go` — session lifecycle، cookie generation
- [ ] بازنویسی `internal/protocol/protocol.go` با binary layout (جایگزین `gob`)
- [ ] Integration test: data transfer end-to-end از طریق SYN-TFO

### Phase 4 — Firewall خودکار + macOS/Windows (Sprint 4، ~۱ هفته)

- [ ] `internal/firewall/firewall.go` interface
- [ ] `internal/firewall/linux.go` — iptables apply + cleanup با signal handler
- [ ] `internal/firewall/darwin.go` — pf
- [ ] `internal/firewall/windows.go` — netsh
- [ ] config field `server.firewall.auto`
- [ ] CI matrix برای ۳ سکو
- [ ] End-to-end test با curl از طریق SOCKS5 → SYN-TFO → اینترنت

### Phase 5 — اختیاری: backend بدون CGO (آینده)

- [ ] `internal/transport/synraw/linux.go` با AF_PACKET (no CGO)
- [ ] `internal/transport/synraw/darwin.go` با /dev/bpf
- [ ] build tag `nocgo` برای انتخاب backend
- [ ] CI matrix دوم با `CGO_ENABLED=0`

### Phase 6 — Transport های اضافی (آینده)

- [ ] SYN-ACK Transport
- [ ] UDP Transport (برای benchmark)
- [ ] Raw IP Transport

---

## 19. ریسک‌ها و چالش‌ها

### ریسک 1: واگرایی از upstream paqet
**مشکل:** اگر paqet تکامل پیدا کند، merge تغییرات upstream به ctun سخت می‌شود.  
**راه‌حل:** تغییرات ctun را تا حد ممکن در فایل‌های **جدید** نگه می‌داریم (`internal/transport/`, `internal/crypto/`, `internal/session/`, `internal/firewall/`). تغییرات در فایل‌های paqet محدود به `send_handle.go`, `recv_handle.go`, `protocol.go`, و `conf/` می‌شود. هر سه ماه یک بار `git merge upstream/master` و حل تضاد محدود.

### ریسک 2: CGO و libpcap
**مشکل:** cross-compilation سخت‌تر؛ نیاز به cross-compiler برای ARM/MIPS.  
**راه‌حل:** Phase 5 یک backend بدون CGO اضافه می‌کند. تا آن زمان، release ها فقط برای Linux amd64/arm64، macOS amd64/arm64، Windows amd64 ساخته می‌شوند (همان matrix paqet).

### ریسک 3: MTU و Fragmentation
**مشکل:** بعضی مسیرها MTU < 1500 دارند؛ SYN با payload بزرگ ممکن است drop شود.  
**راه‌حل:** MTU پیش‌فرض ۱۳۵۰ بایت. KCP retransmit این را خودکار handle می‌کند.

### ریسک 4: Middlebox-های sensitive به SYN با payload
**مشکل:** برخی فایروال‌ها SYN با payload (حتی با TFO option معتبر) را مشکوک می‌بینند.  
**راه‌حل:** KCP retransmit کمک می‌کند. در آینده SYN-ACK Transport می‌تواند جایگزین باشد. paqet flag cycling هم موجود است (`local_flag: ["S", "PA"]` → SYN ها بین حالت‌های مختلف rotate می‌شوند) — این یک fallback خوب اگر pure SYN مسدود شد.

### ریسک 5: iptables/pf rule collision
**مشکل:** rule اضافه‌شده توسط ctun ممکن است با rule موجود conflict داشته باشد.  
**راه‌حل:** rule ها با comment یکتای `ctun-<port>` ثبت می‌شوند. cleanup فقط همان comment ها را پاک می‌کند. signal handler با `defer` تضمین cleanup حتی در crash.

### ریسک 6: Sequence number و source port pattern
**مشکل:** اگر `Seq` و `SrcPort` ما pattern داشته باشند، تشخیص آسان است.  
**راه‌حل:** Seq هر پکت `rand.Uint32()`. Src port از range ephemeral (32768-60999) تصادفی. paqet در حال حاضر همین کار را می‌کند.

### ریسک 7: paqet `local_flag`/`remote_flag` ممکن است با SYN-only crash کند
**مشکل:** کد paqet با `local_flag: ["S"]` تست نشده — ممکن است assume کند که PA flag است.  
**راه‌حل:** اولین چیزی که در Phase 0 تست می‌کنیم. اگر مشکل بود، در Phase 1 با کار روی SYN-TFO transport برطرف می‌شود.

### ریسک 8: License و attribution
**مشکل:** paqet MIT است؛ باید attribution نگه داریم.  
**راه‌حل:** فایل `LICENSE` paqet را نگه می‌داریم و یک `NOTICE` اضافه می‌کنیم: "ctun is a fork of paqet by hanselime, MIT-licensed."

---

## Appendix A: جریان کامل یک درخواست در ctun

```
1. کاربر: curl --socks5 localhost:1080 https://example.com

2. ctun client (paqet SOCKS5):
   - CONNECT example.com:443 دریافت می‌شود

3. ctun client (paqet smux):
   - stream جدید روی session KCP

4. ctun client (paqet KCP):
   - داده به segment های KCP تقسیم می‌شود

5. ctun client (Security — جدید):
   - HKDF کلیدها از PSK
   - هر segment با ChaCha20-Poly1305 رمزنگاری
   - sequence number و header اضافه می‌شود

6. ctun client (SYN-TFO Transport):
   - هر ciphertext → یک SYN packet با TFO option (cookie) و payload
   - ارسال از طریق pcap.Handle

7. [شبکه: فقط SYN packet ها دیده می‌شوند]

8. ctun server (firewall — جدید):
   - iptables NOTRACK + DROP — کرنل به این SYN ها پاسخ نمی‌دهد

9. ctun server (SYN-TFO Transport):
   - pcap.Handle SYN را capture می‌کند
   - TFO cookie چک می‌شود — اگر نامعتبر، silent drop

10. ctun server (Security):
    - decrypt با ChaCha20-Poly1305
    - anti-replay window check

11. ctun server (paqet KCP):
    - segment ها reassemble می‌شوند

12. ctun server (paqet smux):
    - stream مربوطه پیدا می‌شود

13. ctun server (paqet proxy):
    - net.Dial("tcp", "example.com:443")
    - داده رد و بدل می‌شود

14. برگشت: جواب سرور مقصد → همان مسیر معکوس
    - سرور ctun → SYN packets → کلاینت ctun → SOCKS5 → curl
```

---

## Appendix B: مقایسه — ctun (fork) vs paqet (upstream) vs بازنویسی از صفر

| ویژگی | ctun (fork) | paqet (upstream) | بازنویسی از صفر |
|--------|-------------|-------------------|------------------|
| زبان | Go | Go | Go |
| نقطه شروع | fork paqet | — | greenfield |
| TCP SYN-only mode | ✅ سفت‌کاری شده | ✅ via `flag: ["S"]` | ✅ |
| TCP Fast Open option | ✅ Kind=34 + cookie | ❌ | ✅ |
| Reliability | KCP (ارث) | KCP | KCP |
| Multiplexing | smux (ارث) | smux | smux |
| Cipher | ChaCha20-Poly1305 + AES (paqet) | AES/Salsa/Blowfish | ChaCha20-Poly1305 |
| HKDF | ✅ جدید | ❌ | ✅ |
| Anti-replay | ✅ جدید | ❌ | ✅ |
| HELLO handshake | ✅ جدید | ❌ | ✅ |
| Extensible Transport interface | ✅ refactor | ❌ | ✅ |
| SOCKS5 | ✅ ارث (`txthinking/socks5`) | ✅ | باید پیاده شود |
| Firewall خودکار | ✅ جدید | ⚠️ دستی | ✅ |
| سکوها | Linux + macOS + Windows | Linux + macOS + Windows | Linux + macOS فقط |
| CGO | ✅ (Phase 5: optional no-CGO) | ✅ | برنامه: ❌ |
| تخمین زمان تا MVP | ~۴ هفته | حاضر | ~۸+ هفته |

---

## Appendix C: Checklist `git` برای Phase 0

```bash
# 1. fork از طریق UI گیت‌هاب: hanselime/paqet → <owner>/ctun

# 2. clone
git clone git@github.com:<owner>/ctun.git
cd ctun

# 3. add upstream برای merge های آینده
git remote add upstream https://github.com/hanselime/paqet.git
git fetch upstream

# 4. rename module
find . -type f -name "*.go" -exec sed -i '' 's|paqet/internal|ctun/internal|g' {} +
sed -i '' 's|module paqet|module ctun|' go.mod

# 5. تست build
go mod tidy
go build -o ctun ./
./ctun --help

# 6. branch جدید
git checkout -b ctun/phase-1-transport-interface

# 7. اولین تغییر و commit
```
