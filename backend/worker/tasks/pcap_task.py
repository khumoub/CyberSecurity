import subprocess, os, json, re
from collections import defaultdict
from worker.celery_app import celery_app
from worker.tasks.base import publish_output, update_scan_status, save_findings_to_db
from core.config import settings


@celery_app.task(bind=True, name="worker.tasks.pcap_task.run_pcap_analysis", max_retries=0)
def run_pcap_analysis(self, scan_id: str, org_id: str, asset_id: str, pcap_path: str, options: dict):
    """
    PCAP file analysis using tshark/tcpdump.
    Extracts: connections, protocol distribution, top talkers, suspicious patterns.
    Options:
      - protocol_filter: str  e.g. 'tcp', 'udp', 'http', 'dns', 'all'
    """
    protocol_filter = options.get("protocol_filter", "all")

    if not os.path.exists(pcap_path):
        # pcap_path may be a scan_id → look for uploaded file
        candidate = os.path.join(settings.SCAN_OUTPUT_DIR, f"{pcap_path}.pcap")
        if os.path.exists(candidate):
            pcap_path = candidate
        else:
            update_scan_status(scan_id, "failed", f"PCAP file not found: {pcap_path}")
            return

    update_scan_status(scan_id, "running")
    publish_output(scan_id, f"[pcap] Analysing: {os.path.basename(pcap_path)}")

    findings = []
    connections = defaultdict(int)
    protocols = defaultdict(int)
    dns_queries = []
    http_requests = []
    suspicious = []

    try:
        # ── Protocol distribution ──────────────────────────────────────────
        proto_cmd = [
            "tshark", "-r", pcap_path,
            "-T", "fields", "-e", "frame.protocols",
            "-E", "separator=,",
        ]
        proc = subprocess.run(proto_cmd, capture_output=True, text=True, timeout=120)
        for line in proc.stdout.splitlines():
            for proto in line.split(":"):
                protocols[proto.strip()] += 1

        # ── Connection pairs ───────────────────────────────────────────────
        conn_cmd = [
            "tshark", "-r", pcap_path,
            "-T", "fields",
            "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.dstport",
            "-E", "separator=|",
        ]
        proc = subprocess.run(conn_cmd, capture_output=True, text=True, timeout=120)
        for line in proc.stdout.splitlines():
            parts = line.strip().split("|")
            if len(parts) >= 2 and parts[0] and parts[1]:
                key = f"{parts[0]} → {parts[1]}"
                if len(parts) >= 3 and parts[2]:
                    key += f":{parts[2]}"
                connections[key] += 1

        # ── DNS queries ────────────────────────────────────────────────────
        dns_cmd = [
            "tshark", "-r", pcap_path,
            "-Y", "dns.flags.response == 0",
            "-T", "fields", "-e", "dns.qry.name",
        ]
        proc = subprocess.run(dns_cmd, capture_output=True, text=True, timeout=60)
        dns_queries = list(set(proc.stdout.splitlines()))[:100]

        # ── HTTP requests ──────────────────────────────────────────────────
        http_cmd = [
            "tshark", "-r", pcap_path,
            "-Y", "http.request",
            "-T", "fields", "-e", "http.host", "-e", "http.request.uri",
            "-E", "separator=|",
        ]
        proc = subprocess.run(http_cmd, capture_output=True, text=True, timeout=60)
        http_requests = [l.strip() for l in proc.stdout.splitlines() if l.strip()][:100]

        # ── Suspicious patterns ────────────────────────────────────────────
        # Cleartext credentials
        cleartext_cmd = [
            "tshark", "-r", pcap_path,
            "-Y", 'http contains "password" || ftp contains "PASS" || telnet contains "password"',
            "-T", "fields", "-e", "frame.number", "-e", "frame.time",
        ]
        proc = subprocess.run(cleartext_cmd, capture_output=True, text=True, timeout=60)
        if proc.stdout.strip():
            suspicious.append("Possible cleartext credentials detected in HTTP/FTP/Telnet traffic")
            findings.append({
                "title": "Cleartext credentials detected in network traffic",
                "description": "PCAP analysis found possible plaintext password transmission in HTTP, FTP, or Telnet traffic.",
                "severity": "critical",
                "affected_component": os.path.basename(pcap_path),
                "remediation": "Replace cleartext protocols (HTTP/FTP/Telnet) with encrypted alternatives (HTTPS/SFTP/SSH).",
            })

        # Unencrypted protocols
        for bad_proto, sev, title in [
            ("telnet", "high", "Telnet traffic detected (unencrypted)"),
            ("ftp", "medium", "FTP traffic detected (credentials may be cleartext)"),
        ]:
            cmd = ["tshark", "-r", pcap_path, "-Y", bad_proto, "-T", "fields", "-e", "frame.number"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if proc.stdout.strip():
                frame_count = len(proc.stdout.strip().splitlines())
                findings.append({
                    "title": title,
                    "description": f"{frame_count} {bad_proto.upper()} frames detected. Credentials may be transmitted in plaintext.",
                    "severity": sev,
                    "affected_component": "Network traffic",
                    "remediation": f"Replace {bad_proto.upper()} with an encrypted alternative.",
                })

        # Top talkers
        top_connections = sorted(connections.items(), key=lambda x: x[1], reverse=True)[:20]

        publish_output(scan_id, f"[pcap] Protocols seen: {', '.join(list(protocols.keys())[:10])}")
        publish_output(scan_id, f"[pcap] Unique connections: {len(connections)}")
        publish_output(scan_id, f"[pcap] DNS queries: {len(dns_queries)}")
        publish_output(scan_id, f"[pcap] HTTP requests: {len(http_requests)}")
        publish_output(scan_id, f"[pcap] Suspicious patterns: {len(suspicious)}")

        # Store analysis summary in Redis for frontend retrieval
        import redis, json as _json
        r = redis.Redis.from_url(settings.REDIS_URL)
        summary = {
            "scan_id": scan_id,
            "protocols": dict(list(protocols.items())[:20]),
            "top_connections": [{"pair": k, "packets": v} for k, v in top_connections],
            "dns_queries": dns_queries[:50],
            "http_requests": http_requests[:50],
            "suspicious": suspicious,
            "total_connections": len(connections),
        }
        r.setex(f"pcap_summary:{scan_id}", 3600, _json.dumps(summary))
        publish_output(scan_id, _json.dumps({"type": "pcap_summary", **summary}))

    except FileNotFoundError:
        publish_output(scan_id, "[pcap] tshark not found. Install: apt-get install tshark")
        update_scan_status(scan_id, "failed", "tshark not found")
        return
    except Exception as exc:
        update_scan_status(scan_id, "failed", str(exc))
        return

    save_findings_to_db(scan_id, org_id, asset_id, findings)
    publish_output(scan_id, f"[pcap] Analysis complete. {len(findings)} security findings.")
    update_scan_status(scan_id, "completed")
