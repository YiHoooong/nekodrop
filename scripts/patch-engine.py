# Applies nekodrop's changes to the staged copy of winawdl's AirDrop engine.
# Usage: python patch-engine.py <staged airdrop folder>
#
# - A stable mDNS instance name (NEKODROP_SERVICE_ID, kept by the client), so
#   an engine restart (a new awdl0 after the radio restarts) shows up on the
#   iPhone as the same device instead of a second one.
# - Spare receiver ports: when 8771 is held by another program the receiver
#   takes the next free one of 8772-8779 (advertised in the mDNS SRV record,
#   so the iPhone follows), instead of waiting for 8771 forever.
# - Sender presents no TLS client certificate.  An iPhone rejects a self-signed
#   one with SSLV3_ALERT_BAD_CERTIFICATE on both /Discover and /Ask; AirDrop
#   receivers accept connections without a client cert, and identity rides in
#   the plist record instead.  Without this the send direction cannot work.
import pathlib
import sys

NL = chr(10)
HELPER = NL.join([
    'SPARE_PORTS = range(8771, 8780)  # nekodrop: the firewall rule allows these',
    '',
    '',
    'def _bind_spare(settings, watcher):',
    '    ports = [settings.port] + [p for p in SPARE_PORTS if p != settings.port]',
    '    for port in ports:',
    '        try:',
    '            return receiver.Receiver(port, settings, watcher)',
    '        except OSError as error:',
    '            if error.errno != errno.EADDRINUSE or port == ports[-1]:',
    '                raise',
    "            logging.warning('port %d held, trying the next', port)",
    '',
    '',
    '',
])

engine = pathlib.Path(sys.argv[1]) / 'engine.py'
text = engine.read_text(encoding='utf-8')
changed = False

old = 'service_id = secrets.token_hex(6)'
new = "service_id = os.environ.get('NEKODROP_SERVICE_ID') or secrets.token_hex(6)"
if new not in text:
    if old not in text:
        sys.exit('engine.py: the service id line moved; update patch-engine.py')
    text = text.replace(old, new, 1)
    if NL + 'import os' + NL not in text:
        text = text.replace(NL + 'import secrets' + NL, NL + 'import os' + NL + 'import secrets' + NL, 1)
    changed = True

old = 'server = receiver.Receiver(self.settings.port, self.settings, self.watcher)'
new = 'server = _bind_spare(self.settings, self.watcher)'
if new not in text:
    if old not in text:
        sys.exit('engine.py: the receiver bind line moved; update patch-engine.py')
    text = text.replace(old, new, 1)
    text = text.replace(NL + 'class ', NL + HELPER + 'class ', 1)
    changed = True

if changed:
    engine.write_text(text, encoding='utf-8')
print('engine patched')

# sender.py: drop the client certificate from the TLS context.  The receiver
# rejects our self-signed cert; a sender without an Apple-issued identity is
# expected to present none at all.
sender = pathlib.Path(sys.argv[1]) / 'sender.py'
text = sender.read_text(encoding='utf-8')
old = NL.join([
    '    certificate, key = identity.ensure_self_signed(keys_dir)',
    '    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)',
    '    # A receiver visible to everyone presents a certificate nothing vouches',
    '    # for, and takes ours the same way.',
    '    context.check_hostname = False',
    '    context.verify_mode = ssl.CERT_NONE',
    '    context.load_cert_chain(certificate, key)',
])
new = NL.join([
    '    # Present no client certificate.  An iPhone in Everyone mode rejects a',
    '    # self-signed one with SSLV3_ALERT_BAD_CERTIFICATE on every connection.',
    '    # AirDrop receivers accept a connection with no client cert; identity',
    '    # is carried in the plist record, not in the TLS client certificate.',
    '    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)',
    '    context.check_hostname = False',
    '    context.verify_mode = ssl.CERT_NONE',
])
if new not in text:
    if old not in text:
        sys.exit('sender.py: the client_context body moved; update patch-engine.py')
    text = text.replace(old, new, 1)
    sender.write_text(text, encoding='utf-8')
    print('sender patched')

# engine.py: follow a receiver that announces itself again.  After a transfer
# in either direction an iPhone withdraws its AirDrop service and comes back
# under a new instance (#4: peer_gone, then WinError 10061 on its old port,
# then every retry failed at once with "gone").  A send to a peer that is gone,
# or refused on its old port, now waits up to FOLLOW_SECONDS for a receiver
# with the same name and sends there.
FOLLOW = [
    (
        '        self._shy_said = 0' + NL,
        '        self._shy_said = 0' + NL +
        '        self._gone_names = {}  # nekodrop: key -> name of receivers that went away' + NL,
    ),
    (
        NL.join([
            '            for key in [key for key in self._peers if key not in located]:',
            '                if self._peers.pop(key).name:',
            '                    gone.append(key)',
        ]),
        NL.join([
            '            for key in [key for key in self._peers if key not in located]:',
            '                old = self._peers.pop(key)',
            '                if old.name:',
            '                    self._gone_names[key] = old.name',
            '                    gone.append(key)',
        ]),
    ),
    (
        '    def link(self, scope):' + NL,
        NL.join([
            '    def find(self, key, wait):',
            '        """nekodrop: the receiver under `key`, or the one that came back with',
            '        its name, waiting up to `wait` seconds for it."""',
            '        deadline = time.monotonic() + wait',
            '        while True:',
            '            with self._lock:',
            '                peer = self._peers.get(key)',
            '                if peer and peer.name:',
            '                    return peer',
            '                name = self._gone_names.get(key)',
            '                if name:',
            '                    for other in self._peers.values():',
            '                        if other.name == name:',
            '                            return other',
            '            if time.monotonic() >= deadline or not self.wanted.is_set():',
            '                return None',
            '            time.sleep(0.5)',
            '',
            '    def went_away(self, key):',
            '        with self._lock:',
            '            return key in self._gone_names',
            '',
            '    def link(self, scope):',
            '',
        ]),
    ),
    (
        NL.join([
            '        peer = self.looking.peer(peer_key)',
            '        if not peer or scope is None:',
            "            failed('gone')",
            '            return',
        ]),
        NL.join([
            '        peer = self.looking.peer(peer_key)',
            '        # None for a receiver that went away: looked for again in _run.',
            '        if (not peer and not self.looking.went_away(peer_key)) or scope is None:',
            "            failed('gone')",
            '            return',
        ]),
    ),
    (
        NL.join([
            '        watch = SendWatch(self.events, key, sender.archive_bytes(files))',
            '        with self._lock:',
        ]),
        NL.join([
            '        watch = SendWatch(self.events, key, sender.archive_bytes(files))',
            '        watch.peer_key = peer_key',
            '        with self._lock:',
        ]),
    ),
    (
        NL.join([
            "        watch.state('asking')",
            '        try:',
            '            outcome = sender.deliver(peer.address, peer.port, scope, self.context,',
            '                                     self.settings.name, files, watch)',
        ]),
        NL.join([
            "        watch.state('asking')",
            '        try:',
            '            if peer is None:',
            '                peer = self.looking.find(watch.peer_key, FOLLOW_SECONDS)',
            '                if peer is None:',
            "                    watch.state('failed', reason='gone')",
            '                    return',
            '            try:',
            '                outcome = sender.deliver(peer.address, peer.port, scope, self.context,',
            '                                         self.settings.name, files, watch)',
            '            except (ConnectionRefusedError, TimeoutError):',
            '                # Refused or silent before answering: the receiver may be',
            '                # announcing itself again on another port.',
            '                if watch.reached or watch.cancelled:',
            '                    raise',
            '                fresh = self.looking.find(watch.peer_key, FOLLOW_SECONDS)',
            '                if fresh is None or (fresh.address, fresh.port) == (peer.address, peer.port):',
            '                    raise',
            "                logging.info('receiver came back on port %d; sending again', fresh.port)",
            '                peer = fresh',
            '                outcome = sender.deliver(peer.address, peer.port, scope, self.context,',
            '                                         self.settings.name, files, watch)',
        ]),
    ),
    (
        'BIND_RETRY_SECONDS = 5' + NL,
        'BIND_RETRY_SECONDS = 5' + NL +
        'FOLLOW_SECONDS = 15  # nekodrop: wait for a receiver that announces itself again' + NL,
    ),
]
engine = pathlib.Path(sys.argv[1]) / 'engine.py'
text = engine.read_text(encoding='utf-8')
changed = False
for old, new in FOLLOW:
    if new in text:
        continue
    if text.count(old) != 1:
        sys.exit('engine.py: a line the receiver-follow patch needs moved; update patch-engine.py')
    text = text.replace(old, new, 1)
    changed = True
if changed:
    engine.write_text(text, encoding='utf-8')
    print('engine: follows receivers that come back')

# sender.py + receiver.py: raise TCP socket buffers to 2 MiB and enable
# TCP_NODELAY.  Windows defaults Wintun (awdl0) TCP buffers to ~64 KiB, which
# caps AirDrop throughput across AWDL's 20-100 ms slot-hop RTTs at ~0.55 MB/s;
# 2 MiB buffers + TCP_NODELAY unlocked 4.5 MB/s peak RX in MT7922 live tests.
TCP_BUF_BYTES = '2 * 1024 * 1024'

sender = pathlib.Path(sys.argv[1]) / 'sender.py'
stext = sender.read_text(encoding='utf-8')
old_s = NL.join([
    '            sock.settimeout(self.timeout)',
    '            sock.connect((self.host, self.port, 0, self.scope))',
])
new_s = NL.join([
    '            sock.settimeout(self.timeout)',
    '            for opt in (socket.SO_SNDBUF, socket.SO_RCVBUF):',
    '                try: sock.setsockopt(socket.SOL_SOCKET, opt, ' + TCP_BUF_BYTES + ')',
    '                except OSError: pass',
    '            try: sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)',
    '            except OSError: pass',
    '            sock.connect((self.host, self.port, 0, self.scope))',
])
if new_s not in stext:
    if old_s not in stext:
        sys.exit('sender.py: connect() socket lines moved; update patch-engine.py')
    stext = stext.replace(old_s, new_s, 1)
    sender.write_text(stext, encoding='utf-8')
    print('sender: 2 MiB TCP buffers + TCP_NODELAY')

receiver = pathlib.Path(sys.argv[1]) / 'receiver.py'
rtext = receiver.read_text(encoding='utf-8')
old_r = NL.join([
    '        super().__init__((\'::\', port), Handler)',
])
new_r = NL.join([
    '        super().__init__((\'::\', port), Handler)',
    '        for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):',
    '            try: self.socket.setsockopt(socket.SOL_SOCKET, opt, ' + TCP_BUF_BYTES + ')',
    '            except OSError: pass',
])
old_r2 = NL.join([
    '    def process_request(self, request, client_address):',
    '        logging.info(\'connection from [%s]:%s\', client_address[0], client_address[1])',
])
new_r2 = NL.join([
    '    def process_request(self, request, client_address):',
    '        for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):',
    '            try: request.setsockopt(socket.SOL_SOCKET, opt, ' + TCP_BUF_BYTES + ')',
    '            except OSError: pass',
    '        try: request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)',
    '        except OSError: pass',
    '        logging.info(\'connection from [%s]:%s\', client_address[0], client_address[1])',
])
rchanged = False
if new_r not in rtext:
    if old_r not in rtext:
        sys.exit('receiver.py: __init__ super() line moved; update patch-engine.py')
    rtext = rtext.replace(old_r, new_r, 1)
    rchanged = True
if new_r2 not in rtext:
    if old_r2 not in rtext:
        sys.exit('receiver.py: process_request() line moved; update patch-engine.py')
    rtext = rtext.replace(old_r2, new_r2, 1)
    rchanged = True
if rchanged:
    receiver.write_text(rtext, encoding='utf-8')
    print('receiver: 2 MiB TCP buffers + TCP_NODELAY')
