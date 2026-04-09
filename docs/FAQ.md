# Frequently* Asked Questions

\* Where frequently means "at least once" :-)

## How does Wispers Connect compare to...

### Tailscale and tsnet

Like Wispers, [Tailscale](https://tailscale.com) uses NAT-traversal to establish
secure connections between computers without the hassle involved in setting up a
classical VPN. Tailscale's main focus is providing a WireGuard-based VPN, but it
also includes [tsnet](https://tailscale.com/docs/features/tsnet), a library
that's quite similar to Wispers Connect. It lets you write a Go server that
shows up as an individual node on your tailnet, even if the computer the server
runs on does not run Tailscale.

What Wispers gives you that Tailscale and tsnet don't:

**Sovereignty and trust** — When using Tailscale, you are forced to trust their
DERP servers not to eavesdrop on your network traffic or impersonate a computer
on your network. As a US-incorporated company, Tailscale is subject to the CLOUD
Act and can be compelled to do exactly that. Wispers is operated by a Swiss
company and, more importantly, the Wispers Hub cryptographically cannot read
your data or impersonate a node, even if compelled to try.

**Multi-language support** — tsnet is Go-only. Wispers Connect is available for
a growing number of languages.

**Mobile support** — You can use Tailscale on Android and iOS through their
mobile client, but like all mobile VPN clients it tends to clash with battery
saving mechanisms on these platforms. Wispers Connect runs natively inside your
app with no VPN tunnel, so there's nothing to clash with.

**No network switching** — Tailscale requires you to switch between tailnets —
you can only be connected to one at a time. Wispers networks are
application-scoped, so each of your apps can be on its own network without you
ever having to think about it.

### ZeroTier and libzt

Like Wispers, [ZeroTier](https://zerotier.com) creates overlay networks using
NAT traversal. It operates at Layer 2, emulating a virtual Ethernet switch,
while Wispers works at the application layer. ZeroTier's main product is a VPN
client, but it also offers [libzt](https://github.com/zerotier/libzt), an
embeddable library similar to Wispers Connect.

What Wispers gives you that ZeroTier and libzt don't:

**Sovereignty and trust** — ZeroTier is also a US company, subject to the CLOUD
Act. You can self-host the network controller, but since version 1.16 this
requires building from source under a commercial license. Even then, you still
need to trust ZeroTier's relay infrastructure unless you also self-host root
servers — a significantly more involved undertaking. With Wispers, the Hub
cryptographically cannot read your data or impersonate a node, regardless of who
operates it.

**Licensing** — libzt is licensed under the Business Source License (BSL 1.1).
Building closed-source commercial applications on top of it requires a
commercial license from ZeroTier. Wispers Connect is MIT-licensed.

**Mobile support** — ZeroTier's mobile apps work but operate as VPN connections,
with the same battery-life trade-offs as any mobile VPN client. On iOS, you can
only join one ZeroTier network at a time. Wispers Connect runs inside your app
with no VPN tunnel.

**No network switching** — Same as with Tailscale: ZeroTier networks are
device-scoped. Wispers networks are application-scoped.

### OpenZiti

[OpenZiti](https://openziti.io) is an open-source (Apache 2.0) zero-trust
networking platform created by [NetFoundry](https://netfoundry.io). When used
with embedded SDKs, it offers end-to-end encryption with similar trust
properties to Wispers — intermediate routers in the network cannot read your
data. Like Wispers, OpenZiti keeps your services "dark". That is, it only
exposes them to the people who use them instead of the entire internet,
dramatically reducing the attack surface.

What Wispers gives you that OpenZiti doesn't:

**Simplicity** — OpenZiti is a full networking platform. A minimal deployment
requires a controller, at least one edge router reachable from the public
internet, and a certificate enrollment flow. Wispers Connect is a library: add
it as a dependency, write a few lines of code, and you're connected.

**Sovereignty without complexity** — OpenZiti does much better than Tailscale
and ZeroTier when it comes to sovereignty: the entire platform is open source
and designed to be self-hosted. Unfortunately, this leaves you with a choice —
use NetFoundry's managed controller (a US company, subject to the CLOUD Act) or
run the whole complex stack yourself. With Wispers, you don't have to choose:
the Hub cryptographically cannot read your data or impersonate a node,
regardless of who operates it.

**Direct connections** — OpenZiti does not do NAT traversal or peer-to-peer
connections. All data flows through its fabric of routers. Wispers establishes
direct connections between peers wherever possible — the Hub is only involved
for signaling and never touches your data.

**Staying dark on mobile** — OpenZiti has SDKs for Android and iOS you can embed
in a mobile app. But to make this work, controller and edge routers must be
reachable from the public internet. Your infrastructure can't stay "dark". With
Wispers Connect, mobile devices can use NAT traversal to connect directly with
your services and they can stay "dark".

### Holepunch and Hyperswarm

[Hyperswarm](https://github.com/holepunchto/hyperswarm) is the networking layer
of the [Holepunch](https://holepunch.to) ecosystem, backed by Tether. It is the
closest alternative to Wispers Connect architecturally: a library for
establishing direct, encrypted peer-to-peer connections with NAT traversal.

What Wispers gives you that Hyperswarm doesn't:

**Multi-language support** — Hyperswarm is JavaScript-only. It runs on Node.js
and on Bare, Holepunch's own lightweight JS runtime for desktop and mobile.
Wispers Connect is available for a growing number of languages.

**Authenticated discovery** — Hyperswarm uses a public
[DHT](https://en.wikipedia.org/wiki/Distributed_hash_table) for peer discovery.
When you look up peers by topic, a malicious DHT node could substitute its own
key during discovery, intercepting the connection. Wispers uses Hub-based
signaling with out-of-band secret exchange — the Hub cannot insert itself into a
connection even if compromised.

**Integration model** — Holepunch is designed as a full application platform
(Pear) with its own runtime, its own packaging, and its own update mechanism.
Wispers Connect is a library you add to your existing application, in your
existing language, with your existing toolchain.

### libp2p

[libp2p](https://libp2p.io) is a modular P2P networking stack that originated
from IPFS and is now used by projects like Ethereum and Filecoin. It is
available in Go, Rust, JavaScript, Python, Nim, and Swift. Of all the
alternatives listed here, libp2p is the most powerful and flexible — and the
most complex.

What Wispers gives you that libp2p doesn't:

**Simplicity** — libp2p is a framework, not a turnkey solution. You assemble
your networking stack from transports, multiplexers, discovery mechanisms, and
security protocols. This makes sense for a blockchain node; less so for an app
developer who wants to connect two peers. Wispers Connect handles transport,
encryption, NAT traversal, and discovery in a single dependency.

**Focus** — libp2p is designed for large-scale decentralized networks with
thousands of participants. Wispers is designed for application-level overlay
networks where you control membership. If you're building the next Ethereum,
use libp2p. If you're building an app that needs a few peers to talk securely,
Wispers will get you there faster.

## Licensing

**Will the Wispers backend be open sourced?** — Maybe. The Wispers Connect
library is MIT-licensed and will stay that way. The backend is currently closed
source, but we'd like to open it up if I can find a sustainable business model
that supports it. In the meantime, the protocol is designed so that the Hub is a
stateless signaling server — if Wispers the company disappeared tomorrow,
running a replacement would be a realistic undertaking, not a moonshot.
