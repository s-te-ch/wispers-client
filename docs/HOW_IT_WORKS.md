# How it works

This document explains the design of Wispers Connect: how nodes find each other,
how they establish trust, and how data moves between them. We'll first cover the
Wispers architecture, then expand to explain how Wispers Connect makes this
available to integrators (i.e. you).

## Wispers architecture

The basic architecture of Wispers consists of:
* Nodes — the programs we want to communicate with each other
* Hub — the rendezvous server for NAT traversal
* Registration UI — here, users register their nodes. Usually a web UI, but
  could be many things

To give an idea how these work together, let's go through a few collaboration
diagrams.

### Node registration

The first thing is to add the nodes we want to communicate to a **connectivity
group**. What exactly a connectivity group corresponds to is use case
specific. In [Wispers Files](https://files.wispers.dev) for example, it
corresponds to a single user and their devices. With the `wconnect` tool's HTTP
proxying, it can mean all the devices having access to a proxied web app.

The sequence generally looks something like this:

<center>
  <img src="images/wispers-registration-collab.svg"
       width="420"
       alt="Collaboration diagram of the registration process"/>
</center>

1. In a first phase, we add all the necessary metadata about the node — name,
   user account, etc. Wispers stores this in a pre-registration and returns a
   registration token, which the UI returns to the node (using manual copying,
   deeplinks, or similar)
2. The node then sends this registration token to the Hub, which turns the
   pre-registration into an actual entry and returns (connectivity group ID,
   device number, auth token), which the node stores locally.

You may wonder why the two-phase registration is necessary. The reason is that
registration often involves things like browser logins, which is hard to do from
the node itself. If your use case can do everything at once, there's no need to
surface the two-phase registration to the user.

### Node activation

Once they are registered in a connectivity group, nodes in the same group can
exchange messages through the hub, but they still have to trust the hub to do
nothing nefarious. After all, it's the classical man-in-the-middle we know from
IT security. Wispers fixes this with a process called "activation".

#### Pairing

The trick is to exchange a code between nodes without involving the Hub. This
could be a human copying the code manually between devices, scanning a QR code,
or anything to that effect. The nodes can then use this code to exchange their
respective public keys while being certain that the hub didn't tamper with them.

<center>
  <img src="images/wispers-activation-phase1.svg"
       width="860"
       alt="Collaboration diagram of the activation process, phase 1"/>
</center>

Each node computes an [HMAC](https://en.wikipedia.org/wiki/HMAC) from its public
key and the activation code. This proves to the receiver that the sender knew
the activation code and must be the peer node from the first step. The hub can't
fake this message because it doesn't know the code.

Once this procedure is complete, both nodes know each other's public keys, which
means that they can always verify that their messages weren't tampered
with. They can also use this to agree on an encryption key to make sure nobody
in-between can read what they send each other.

#### Updating the roster

Now that we have a way to pair nodes, we still run into the problem that this
quickly becomes onerous when the connectivity group grows. For 2 nodes, we need
one pairing; for 5 nodes we already need 10; for 10 nodes we need a full 45
pairings. Not fun.

To make this nicer, we add a second phase to the activation process, in which we
iteratively build up a cryptographic roster for the connectivity group. With
this roster, a node can use transitive trust — if node `n` trusts node `m`
because it's paired with it, and node `m` is also paired with _another_ node
`o`, `n` can also trust `o`. After each pairing, the nodes update the roster,
co-sign it, and store it in the Hub.

<center>
  <img src="images/wispers-activation-phase2.svg"
       width="340"
       alt="Collaboration diagram of the activation process, phase 2"/>
</center>

Nodes can verify this roster by following the history of its creation. Once a
node is paired with another, it can check the roster updates _that_ node has
co-signed and start trusting the nodes involved in those updates. Eventually
this will cover the entire roster. Again, the hub cannot interfere and just
stores the bytes.

#### Bootstrapping

Normally, activation involves a newly registered node (the "new node") and
another, already activated node (the "endorser") — but in a new connectivity
group, nobody has been activated yet and the roster is empty. This is the
bootstrap problem. We can't just consider the first registered node magically
activated because the Hub could use this to trick nodes into trusting a fake
first node.

Instead, we bootstrap the roster with the first pairing. Instead of updating the
existing roster, the nodes co-sign a newly initialised roster that contains just
the two of them. Any two of the registered nodes can do this.

### Establishing peer-to-peer connections

After activation, nodes that want to be reachable stay connected to the hub in
"serving" mode. In essence, they keep a bi-directional gRPC stream open and just
wait for the hub to send them requests to open connections to a peer node.

To open a connection to a serving node (the "answerer"), the "caller" node goes
through a NAT-traversal, relaying messages through the hub.

<center>
  <img src="images/wispers-connection-establishment.svg"
       width="860"
       alt="Collaboration diagram of connection establishment"/>
</center>

There are roughly 3 steps:

1. The caller gets the STUN/TURN config from the hub, gathers its own candidate
   addresses using that STUN server, generates its side of a Diffie-Hellman key
   exchange to establish encryption, and sends all of that to the answerer with
   a `StartConnection` request.
2. The answerer receives the message, gathers its own candidate addresses,
   generates its own side of the Diffie-Hellman key exchange, and sends all of
   that back.
3. Now both caller and answerer have all the information they need. They start
   ICE connection establishment using the embedded [libjuice
   library](https://github.com/paullouisageneau/libjuice) on both ends at the
   same time.

Once this is complete, both nodes can send each other UDP datagrams, encrypted
using the X25519 key established with the StartConnection request and response
messages.

Unfortunately, only a few applications work with UDP. Most want something like
TCP. Because of this, the nodes can also establish a QUIC connection on top of
the already established UDP path. QUIC is basically modernised TCP and
conveniently works on top of UDP. It also comes with TLS built in — which is a
challenge because this is geared towards public servers with TLS
certificates. Luckily, QUIC also supports pre-shared key (PSK) mode, and we have
just established a shared key! So in QUIC mode, Wispers does not encrypt the UDP
datagrams, but instead hands the key to QUIC to use it instead.

## What Wispers Connect adds

Wispers Connect is how you use Wispers in your own software. There are several
integration points:

* The **wispers-connect library** implements everything a Wispers node needs to
  do, with an interface that lets you adapt things to your use case
* The **REST API** at https://connect.wispers.dev/api lets you implement your
  own registration UI. For example, you could call this API from your own web
  app
* The **Connect web app** at https://connect.wispers.dev lets you configure the
  Wispers infrastructure for your needs, e.g. which API keys can be used

### What library clients need to provide

The following diagram illustrates how things fit together when integrating with
Wispers Connect.

<center>
  <img src="images/wispers-connect-components.svg"
       width="512" alt="Wispers Connect components diagram"/>
</center>

The two main things an integrator needs to build are:
* An app linking the wispers-connect library. The library does all the
  communication magic for you, but requires two things:
    * A UI that allows the user to enter registration token and activation code
      (not necessarily a _graphical_ UI)
    * A storage implementation that stores the node's state (root key and hub
      registration), ideally in the host platform's secure storage (e.g. the
      Keychain on macOS)
* An integrator service that manages creating registration tokens using the REST
  API. This will often be your own web app, but could also just be a CLI tool.

To make this more concrete, here's how Wispers Files implements its node
registration:

1. On first open, the app sends the user to https://files.wispers.dev to log in
   and enter details about the device being added. The web app forwards this
   information to the Wispers Connect REST API and receives a registration token
   in return
2. The web app then re-opens the app using a deeplink, handing over the
   registration token. The app detects this, and hands the token over to the
   wispers-connect library, which completes the registration with the hub behind
   the scenes.
3. Once the registration is complete, the library calls back into the app's
   storage implementation to securely store root key, auth token, etc.

### Membership attestations

One problem with the basic way of using Wispers Connect described above is that,
even after registration with the hub, the app can't authenticate itself to the
integrator service. After all, the registration was with the Wispers
infrastructure, not that service.

To solve this problem, the hub issues **membership attestations** together with
the node's registration info. These are cryptographically signed pieces of
information confirming that the node is indeed registered with Wispers under a
certain ID. The integrator service can verify these attestations using the
well-known public key from Wispers and so authenticate the node.

## Security properties

With this design, we achieve the following security properties:

* End-to-end encrypted UDP and QUIC connections between nodes that cannot be
  MITM-ed by the Hub, or even by the cloud provider whose infrastructure the Hub
  runs on
* Forward secrecy: Each connection uses ephemeral X25519 keys, so compromising
  the root key does not expose past sessions
* Roster-based trust that prevents the Hub from injecting nodes

At the time of writing, these are the limitations we're aware of:

* If compromised, a node can do anything a normal node can do, including
  endorsing other, malicious nodes

To mitigate node compromise, Wispers Connect allows any node in the roster to
revoke any other node. However, this comes at the price of an additional DoS
vector — a malicious node could just revoke everyone's roster entries.
