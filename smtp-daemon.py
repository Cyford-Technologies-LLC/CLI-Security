#!/usr/bin/env python3
"""
Cyford Security SMTP Filter Daemon
Sits between Postfix (port 25) and re-injection (port 10026).
Receives mail via SMTP, pipes it through the PHP security filter,
which handles spam/quarantine and re-injects clean mail to port 10026.
"""

import asyncio
import logging
import os
import re
import signal
import subprocess
import sys

# ── Configuration ──────────────────────────────────────────────────────────────
LISTEN_HOST = '172.21.0.1'   # Docker bridge — only the container can reach us
LISTEN_PORT = 10025
PHP_BINARY  = '/usr/bin/php'
PHP_SCRIPT  = '/opt/cyford/security/index.php'
LOG_FILE    = '/var/log/cyford-security/smtp-daemon.log'
MAX_SIZE    = 30 * 1024 * 1024   # 30 MB message limit
PHP_TIMEOUT = 120                 # seconds per message
# ───────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger('cyford-smtp-daemon')


class SMTPSession:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader  = reader
        self.writer  = writer
        self.peer    = writer.get_extra_info('peername')
        self.peer_ip = self.peer[0] if self.peer else '127.0.0.1'

        self.mail_from = ''
        self.rcpt_to:  list[str] = []
        self.data:     bytes = b''

    # ── Low-level I/O ──────────────────────────────────────────────────────────

    async def _send(self, line: str):
        self.writer.write((line + '\r\n').encode())
        await self.writer.drain()

    async def _readline(self, timeout=300) -> str:
        line = await asyncio.wait_for(self.reader.readline(), timeout=timeout)
        return line.decode('utf-8', errors='replace').rstrip('\r\n')

    # ── SMTP DATA reader ───────────────────────────────────────────────────────

    async def _read_data(self) -> bytes:
        """Read SMTP DATA section (terminated by CRLF.CRLF), un-stuff dots."""
        buf = bytearray()
        while True:
            raw = await asyncio.wait_for(self.reader.readline(), timeout=300)
            if raw in (b'.\r\n', b'.\n'):
                break
            if raw.startswith(b'..'):        # RFC 5321 dot-stuffing
                raw = raw[1:]
            buf.extend(raw)
            if len(buf) > MAX_SIZE:
                # Drain and reject
                while raw not in (b'.\r\n', b'.\n'):
                    raw = await asyncio.wait_for(self.reader.readline(), timeout=300)
                raise ValueError('Message exceeds size limit')
        return bytes(buf)

    # ── SMTP verb helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _extract_address(args: str) -> str:
        m = re.search(r'<([^>]*)>', args)
        return m.group(1) if m else args.strip()

    # ── Core processing ────────────────────────────────────────────────────────

    async def _process(self):
        """Pipe the collected email through the PHP security script."""
        if not self.rcpt_to:
            log.warning(f'{self.peer_ip}: no recipients, skipping')
            return

        for recipient in self.rcpt_to:
            log.info(f'{self.peer_ip}: processing → {recipient}')
            try:
                proc = await asyncio.create_subprocess_exec(
                    PHP_BINARY, PHP_SCRIPT,
                    '--input_type=postfix',
                    f'--recipient={recipient}',
                    f'--ips={self.peer_ip}',
                    '--categories=3',
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(input=self.data),
                    timeout=PHP_TIMEOUT,
                )
                rc = proc.returncode
                if rc != 0:
                    log.error(
                        f'{self.peer_ip}: PHP exited {rc} for {recipient}: '
                        f'{stderr.decode(errors="replace")[:500]}'
                    )
                else:
                    log.info(f'{self.peer_ip}: OK for {recipient}')
                    if stderr:
                        log.debug(f'PHP stderr: {stderr.decode(errors="replace")[:200]}')
            except asyncio.TimeoutError:
                log.error(f'{self.peer_ip}: PHP timed out for {recipient}')
            except Exception as exc:
                log.error(f'{self.peer_ip}: error for {recipient}: {exc}')

    # ── SMTP state machine ─────────────────────────────────────────────────────

    async def handle(self):
        log.info(f'Connection from {self.peer_ip}')
        await self._send('220 Cyford Security Filter ESMTP ready')

        try:
            while True:
                line = await self._readline()
                if not line:
                    break

                parts = line.split(' ', 1)
                verb  = parts[0].upper()
                args  = parts[1] if len(parts) > 1 else ''

                if verb in ('EHLO', 'HELO'):
                    await self._send('250-cyford-security-filter')
                    await self._send('250-PIPELINING')
                    await self._send('250-SIZE 31457280')
                    await self._send('250 OK')

                elif verb == 'MAIL':
                    self.mail_from = self._extract_address(args)
                    await self._send('250 OK')

                elif verb == 'RCPT':
                    addr = self._extract_address(args)
                    if addr:
                        self.rcpt_to.append(addr)
                    await self._send('250 OK')

                elif verb == 'DATA':
                    await self._send('354 End data with <CR><LF>.<CR><LF>')
                    try:
                        self.data = await self._read_data()
                    except ValueError as exc:
                        await self._send(f'552 {exc}')
                        self._reset()
                        continue

                    await self._process()
                    await self._send('250 OK: queued by Cyford Security Filter')
                    self._reset()

                elif verb == 'RSET':
                    self._reset()
                    await self._send('250 OK')

                elif verb == 'NOOP':
                    await self._send('250 OK')

                elif verb == 'QUIT':
                    await self._send('221 Bye')
                    break

                else:
                    await self._send('502 Command not implemented')

        except asyncio.TimeoutError:
            log.warning(f'{self.peer_ip}: connection timed out')
        except ConnectionResetError:
            log.info(f'{self.peer_ip}: connection reset by peer')
        except Exception as exc:
            log.error(f'{self.peer_ip}: unhandled error: {exc}')
        finally:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass
            log.info(f'{self.peer_ip}: connection closed')

    def _reset(self):
        self.mail_from = ''
        self.rcpt_to   = []
        self.data      = b''


# ── Server bootstrap ───────────────────────────────────────────────────────────

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    session = SMTPSession(reader, writer)
    await session.handle()


async def main():
    # Verify PHP script exists
    if not os.path.isfile(PHP_SCRIPT):
        log.critical(f'PHP script not found: {PHP_SCRIPT}')
        sys.exit(1)

    server = await asyncio.start_server(
        handle_client,
        LISTEN_HOST,
        LISTEN_PORT,
        limit=MAX_SIZE + 1024,
    )

    addrs = ', '.join(str(s.getsockname()) for s in server.sockets)
    log.info(f'Cyford Security SMTP daemon listening on {addrs}')

    loop = asyncio.get_running_loop()

    def _shutdown():
        log.info('Shutdown signal received')
        server.close()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _shutdown)

    async with server:
        await server.serve_forever()

    log.info('Daemon stopped')


if __name__ == '__main__':
    asyncio.run(main())
