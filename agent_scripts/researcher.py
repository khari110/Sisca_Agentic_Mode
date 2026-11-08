import sys
import os
import re
import json
import time
import random
import hashlib
import asyncio
from datetime import datetime

from google import genai
from google.genai import types
from playwright.async_api import async_playwright

# ---------------------------------------------------------------- config
# Sab kuch env se override ho sakta hai (docker-compose.yml -> environment:), code badalne ki zarurat nahi.
MODEL = os.environ.get("SISCA_AGENT_MODEL", "gemini-3-flash-preview")   # pinned; "gemini-flash-latest" alias ka kuch pata nahi kab badal jaye
FALLBACK_MODEL = "gemini-flash-latest"       # agar pinned model "not found" nikle
THINKING_LEVEL = os.environ.get("SISCA_THINKING_LEVEL", "low").upper()   # MINIMAL | LOW | MEDIUM | HIGH (Gemini 3 family)
CALL_TIMEOUT_MS = int(os.environ.get("SISCA_CALL_TIMEOUT_MS", "30000"))  # ek API call par max 30s, phir agli key
CALL_BUDGET_SEC = int(os.environ.get("SISCA_CALL_BUDGET_SEC", "120"))    # ek step ke saare retries ka total budget
TEXT_FIRST = os.environ.get("SISCA_TEXT_FIRST", "1") == "1"              # 1 = page text pehle, screenshot sirf zarurat par
PLAN_MEMORY = os.environ.get("SISCA_PLAN_MEMORY", "0") == "1"            # 1 = todo.md style plan memory (optional extra)
MAX_TEXT_CHARS = int(os.environ.get("SISCA_MAX_TEXT_CHARS", "12000"))    # model ko ek step me itna page text
TODO_FILE = "/app/agent_scripts/todo.md"
TODO_MAX_CHARS = 1500

VIEW_W, VIEW_H = 1280, 720
MAX_STEPS = 60
TIME_BUDGET_SEC = 17 * 60          # mainapp.py kills us at 20 min, so finish gracefully before that
MAX_CONSECUTIVE_FAILS = 5          # stop early (with the real reason) instead of looping silently
LOG_FILE = "/app/agent_scripts/agent_run.log"   # visible on the host via the ./agent_scripts volume

# Errors for which switching to another API key / waiting can help.
# NOTE: bare "400" removed - a malformed request (e.g. bad thinking config) is not a key problem.
ROTATE_HINTS = ("429", "resource_exhausted", "exhausted", "quota", "api_key", "api key",
                "403", "permission_denied", "500", "internal", "503", "unavailable", "overloaded",
                "deadline", "timed out", "timeout", "connection", "reset by peer")

# Pages where a screenshot is needed even in text-first mode
BLOCK_PATTERNS = re.compile(
    r"unusual traffic|captcha|verify you are (a )?human|are you a robot|access denied|"
    r"just a moment|enable javascript|checking your browser|before you continue|accept all cookies",
    re.I)


def log(msg):
    """Progress goes to stderr + a log file. stdout is reserved for the FINAL report only
    (mainapp.py shows stdout to the user)."""
    line = f"{datetime.now():%H:%M:%S} {msg}"
    print(line, file=sys.stderr, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


# ---------------------------------------------------------------- model helpers
def make_client(key):
    """Client with a hard HTTP timeout so one hung request cannot block the agent for minutes."""
    try:
        return genai.Client(api_key=key, http_options=types.HttpOptions(timeout=CALL_TIMEOUT_MS))
    except Exception:
        return genai.Client(api_key=key)      # very old SDK without HttpOptions.timeout


def initial_thinking_mode(model):
    m = model.lower()
    if "gemini-3" in m or "latest" in m:      # the *-latest alias currently follows the Gemini 3 family
        return "level"
    if "2.5" in m and "pro" not in m:
        return "budget0"
    return "none"


class KeyPool:
    def __init__(self, keys):
        self.keys = keys
        self.i = random.randrange(len(keys))
        self.client = make_client(keys[self.i])
        self.model = MODEL
        self.think = initial_thinking_mode(MODEL)   # level | budget0 | none (auto-downgrades on API errors)
        self.model_calls = 0
        self.model_secs = 0.0

    def rotate(self):
        self.i = (self.i + 1) % len(self.keys)
        self.client = make_client(self.keys[self.i])

    def gen_config(self):
        kwargs = dict(response_mime_type="application/json", temperature=0.2)
        try:
            if self.think == "level":
                kwargs["thinking_config"] = types.ThinkingConfig(thinking_level=THINKING_LEVEL)
            elif self.think == "budget0":
                kwargs["thinking_config"] = types.ThinkingConfig(thinking_budget=0)
        except Exception as e:                       # SDK too old for thinking_level
            log(f"  thinking config not supported by this SDK ({str(e)[:80]}), continuing without it")
            self.think = "none"
        return types.GenerateContentConfig(**kwargs)


def response_text(resp):
    """resp.text can be None (blocked / empty / thinking-only). Fall back to raw parts."""
    try:
        if resp.text:
            return resp.text
    except Exception:
        pass
    parts = []
    for cand in (getattr(resp, "candidates", None) or []):
        for part in (getattr(getattr(cand, "content", None), "parts", None) or []):
            if getattr(part, "text", None):
                parts.append(part.text)
    return "".join(parts)


def extract_command(text):
    """Find the first JSON object in the model output, even with prose / ``` fences around it."""
    if not text:
        return None
    start = text.find("{")
    if start == -1:
        return None
    try:
        obj, _ = json.JSONDecoder().raw_decode(text[start:])
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None


async def ask_model(pool, image_bytes, prompt):
    """Returns (text, error). image_bytes may be None (text-only step).
    Rotates keys on quota/key/overload errors, auto-downgrades unsupported thinking config,
    falls back to FALLBACK_MODEL if the pinned model does not exist, and gives up after CALL_BUDGET_SEC."""
    contents = [prompt]
    if image_bytes:
        contents = [types.Part.from_bytes(data=image_bytes, mime_type="image/jpeg"), prompt]

    max_attempts = len(pool.keys) * 2 + 3
    started = time.time()
    last_error = None
    for attempt in range(1, max_attempts + 1):
        if time.time() - started > CALL_BUDGET_SEC:
            return None, f"model call budget ({CALL_BUDGET_SEC}s) used up; last error: {(last_error or '')[:200]}"
        t0 = time.time()
        try:
            resp = await asyncio.to_thread(
                pool.client.models.generate_content,
                model=pool.model,
                contents=contents,
                config=pool.gen_config(),
            )
            dt = time.time() - t0
            pool.model_calls += 1
            pool.model_secs += dt
            log(f"  model={pool.model} think={pool.think} image={'yes' if image_bytes else 'no'} took {dt:.1f}s")
            return response_text(resp), None
        except Exception as e:
            last_error = str(e)
            low = last_error.lower()

            # 1) thinking config not accepted by this model -> downgrade and retry (same key)
            if "thinking" in low and pool.think != "none":
                nxt = "budget0" if pool.think == "level" else "none"
                log(f"  thinking mode '{pool.think}' rejected ({last_error[:120]}) -> trying '{nxt}'")
                pool.think = nxt
                continue

            # 2) model name does not exist for this key/API version -> fallback alias (same key)
            if ("not found" in low or "404" in low or "not supported for generatecontent" in low) \
                    and "api key" not in low and pool.model != FALLBACK_MODEL:
                log(f"  model '{pool.model}' unavailable ({last_error[:120]}) -> falling back to '{FALLBACK_MODEL}'")
                pool.model = FALLBACK_MODEL
                pool.think = initial_thinking_mode(FALLBACK_MODEL)
                continue

            if any(h in low for h in ROTATE_HINTS):
                log(f"  API error (attempt {attempt}/{max_attempts}, {time.time() - t0:.1f}s), rotating key: {last_error[:160]}")
                pool.rotate()
                # after we've tried every key once, wait a bit (per-minute quota)
                await asyncio.sleep(8 if attempt % len(pool.keys) == 0 else 1)
            else:
                log(f"  Non-retryable API error: {last_error[:300]}")
                return None, last_error
    return None, last_error


# ---------------------------------------------------------------- browser helpers
def to_px(x, y):
    """Model is asked for a 0-1000 grid (Gemini's native coordinate space). If it sends >1000 it
    clearly used pixels, so keep those."""
    x, y = float(x), float(y)
    if x > 1000 or y > 1000:
        px, py = x, y
    else:
        px, py = x / 1000 * VIEW_W, y / 1000 * VIEW_H
    return int(min(max(px, 0), VIEW_W - 1)), int(min(max(py, 0), VIEW_H - 1))


async def execute(page, cmd):
    action = cmd.get("action")
    if action == "click":
        px, py = to_px(cmd["x"], cmd["y"])
        await page.mouse.click(px, py)
        await asyncio.sleep(2)
    elif action == "click_text":
        # click by visible text - works without a screenshot (text-first mode)
        await page.get_by_text(str(cmd["text"]), exact=False).first.click(timeout=8000)
        await asyncio.sleep(2)
    elif action == "type":
        await page.keyboard.type(str(cmd["text"]), delay=60)
        if cmd.get("submit"):
            await page.keyboard.press("Enter")
            await asyncio.sleep(3)
        else:
            await asyncio.sleep(1)
    elif action == "press_key":
        await page.keyboard.press(str(cmd["key"]))
        await asyncio.sleep(3)
    elif action == "scroll":
        await page.mouse.move(VIEW_W // 2, VIEW_H // 2)
        amount = 600 if str(cmd.get("direction", "down")).lower() != "up" else -600
        await page.mouse.wheel(0, amount)
        await asyncio.sleep(1.5)
    elif action == "goto":
        url = str(cmd["url"]).strip()
        if not re.match(r"^https?://", url):
            url = "https://" + url
        await page.goto(url, wait_until="domcontentloaded", timeout=45000)
        await asyncio.sleep(2)
    elif action == "wait":
        await asyncio.sleep(min(max(float(cmd.get("seconds", 4)), 1), 15))
    else:
        raise ValueError(f"unknown action '{action}'")


# ---------------------------------------------------------------- page text + plan memory
async def get_page_text(page):
    """Whole-page visible text (not just the viewport) - this is what lets the agent skip scroll steps."""
    try:
        t = await page.inner_text("body", timeout=8000)
    except Exception:
        return ""
    t = re.sub(r"[ \t\r\f\v]+", " ", t)
    t = re.sub(r"\n\s*\n+", "\n", t)
    return t.strip()


def read_todo():
    if not PLAN_MEMORY:
        return ""
    try:
        with open(TODO_FILE, "r", encoding="utf-8") as f:
            return f.read()[:TODO_MAX_CHARS]
    except Exception:
        return ""


def write_todo(text):
    if not PLAN_MEMORY:
        return
    try:
        with open(TODO_FILE, "w", encoding="utf-8") as f:
            f.write(text[:TODO_MAX_CHARS])
    except Exception:
        pass


def build_prompt(query, url, title, history, text_block, has_image, todo):
    hist = "\n".join(history[-8:]) if history else "(none yet - this is the first step)"

    if has_image:
        seen = f"You see a screenshot of the browser page (viewport {VIEW_W}x{VIEW_H})."
    else:
        seen = ("NO screenshot is attached this step - the full page text is given below instead. "
                "If you really need to see the layout (to click by coordinates), answer {\"action\": \"look\"}.")
    if text_block:
        seen += "\n\n" + text_block

    plan = ""
    if PLAN_MEMORY:
        plan = f"""
PLAN MEMORY (todo.md) - your own checklist, kept between steps:
{todo if todo.strip() else "(empty - create it now)"}
In EVERY reply add a field "todo": the full updated checklist as a short markdown string (max 6 lines,
- [ ] pending, - [x] done). Keep it short; it is not shown to the user.
"""

    return f"""
You are an autonomous web-browsing agent. Your goal: "{query}"

{seen}
Current URL: {url}
Page title: {title}

Return EXACTLY ONE action as a single JSON object (no prose). Allowed actions:
1. {{"action": "click", "x": 500, "y": 420, "reason": "..."}}  -> x,y are on a 0-1000 grid: (0,0)=top-left, (1000,1000)=bottom-right of the screenshot (needs a screenshot)
2. {{"action": "click_text", "text": "Infinix Hot 50", "reason": "..."}}  -> click the first element containing this visible text (works without a screenshot)
3. {{"action": "type", "text": "infinix mobile prices priceoye", "submit": true, "reason": "..."}}  -> types into the focused field; submit=true also presses Enter
4. {{"action": "press_key", "key": "Enter", "reason": "..."}}
5. {{"action": "scroll", "direction": "down", "reason": "..."}}  -> scroll (also loads lazy content; the page text is refreshed afterwards)
6. {{"action": "goto", "url": "https://www.priceoye.pk", "reason": "..."}}  -> open a URL directly (search URLs like https://www.google.com/search?q=... are fine)
7. {{"action": "read_more", "reason": "..."}}  -> show the NEXT part of the page text when it says "more available"
8. {{"action": "look", "reason": "..."}}  -> attach a screenshot on the next step
9. {{"action": "wait", "seconds": 5, "reason": "..."}}
10. {{"action": "finish", "data": "Bulleted report with the actual names/prices/values you read from the pages.", "reason": "..."}}

RULES:
- Prefer READING the page text: if it already contains the data the goal needs, finish immediately - do not scroll or click for nothing.
- To type into a field by coordinates, FIRST click it (one step), THEN type (next step). Check the previous actions below.
- Close cookie banners / pop-ups first if they block the page.
- If Google shows a CAPTCHA / "unusual traffic" page, use goto with https://duckduckgo.com or https://www.bing.com instead.
- If the task names a website, open that website (via goto or search), read the real data, then finish.
- Only use "finish" when you have actual data from the pages. Never invent numbers.
- If a previous action says "screen did not change", do something DIFFERENT (other coordinates, other action).
{plan}
Previous actions:
{hist}
"""


# ---------------------------------------------------------------- main loop
async def agent_loop(context, page, query, pool):
    history = []
    deadline = time.time() + TIME_BUDGET_SEC
    run_started = time.time()
    fails = 0
    last_sig = None
    last_error = "unknown"
    force_look = False          # model asked for a screenshot
    last_failed = False         # previous action raised -> look at the page
    view = {"url": None, "offset": 0}   # text window state (read_more)

    if PLAN_MEMORY:
        write_todo("")

    for step in range(1, MAX_STEPS + 1):
        if time.time() > deadline:
            return None, "time budget (17 min) used up"
        step_started = time.time()

        # a click may open a new tab - follow it
        if len(context.pages) > 1 and context.pages[-1] is not page:
            page = context.pages[-1]
            try:
                await page.bring_to_front()
            except Exception:
                pass

        # ---- observe: text first, screenshot only when needed
        try:
            url = page.url
            title = await page.title()
            text = await get_page_text(page) if TEXT_FIRST else ""
        except Exception as e:
            fails += 1
            last_error = f"page read failed: {e}"
            log(f"[Step {step}] {last_error}")
            if fails >= MAX_CONSECUTIVE_FAILS:
                return None, last_error
            await asyncio.sleep(2)
            continue

        base_url = url.split("#")[0]
        if view["url"] != base_url:
            view["url"], view["offset"] = base_url, 0

        need_image = (not TEXT_FIRST) or force_look or last_failed or len(text) < 300 \
            or bool(BLOCK_PATTERNS.search(text[:4000]))
        shot = None
        if need_image:
            try:
                shot = await page.screenshot(type="jpeg", quality=70)
            except Exception as e:
                log(f"[Step {step}] screenshot failed: {e}")
                if not text:
                    fails += 1
                    last_error = f"screenshot failed: {e}"
                    if fails >= MAX_CONSECUTIVE_FAILS:
                        return None, last_error
                    await asyncio.sleep(2)
                    continue
        force_look = False

        # change detection: text signature when we have text, screenshot hash otherwise
        sig = hashlib.md5((url + text).encode("utf-8", "ignore")).hexdigest() if text \
            else (hashlib.md5(shot).hexdigest() if shot else None)
        if history and sig and sig == last_sig and not history[-1].endswith("[screen did not change]"):
            history[-1] += " [screen did not change]"
        last_sig = sig

        text_block = ""
        if text:
            off = min(view["offset"], max(len(text) - 1, 0))
            chunk = text[off:off + MAX_TEXT_CHARS]
            end = off + len(chunk)
            more = " - more available, use read_more" if end < len(text) else " - end of page text"
            text_block = f"PAGE TEXT (chars {off}-{end} of {len(text)}{more}):\n<<<\n{chunk}\n>>>"

        log(f"[Step {step}] url={url} text={len(text)}ch image={'yes' if shot else 'no'}")
        prompt = build_prompt(query, url, title, history, text_block, bool(shot), read_todo())
        out, err = await ask_model(pool, shot, prompt)
        cmd = extract_command(out)

        if not cmd:
            fails += 1
            last_error = err or f"model returned no usable JSON: {(out or '')[:120]!r}"
            log(f"  no action ({fails}/{MAX_CONSECUTIVE_FAILS}): {last_error}")
            if fails >= MAX_CONSECUTIVE_FAILS:
                return None, last_error
            await asyncio.sleep(2)
            continue

        action = cmd.get("action")
        reason = cmd.get("reason", "")
        log(f"  action={action} {json.dumps({k: v for k, v in cmd.items() if k not in ('reason', 'data', 'todo')}, ensure_ascii=False)} | {reason}")

        if PLAN_MEMORY and isinstance(cmd.get("todo"), str) and cmd["todo"].strip():
            write_todo(cmd["todo"])
            log("  todo.md updated: " + cmd["todo"].strip().replace("\n", " | ")[:200])

        if action == "finish":
            log(f"Done in {time.time() - run_started:.0f}s total, {pool.model_calls} model calls "
                f"({pool.model_secs:.0f}s waiting on the model), {step} steps")
            return cmd.get("data") or "Research workflow finished.", None

        try:
            if action == "look":
                force_look = True
            elif action == "read_more":
                if view["offset"] + MAX_TEXT_CHARS < len(text):
                    view["offset"] += MAX_TEXT_CHARS
                else:
                    log("  read_more: already at the end of the page text")
            else:
                if action in ("goto", "scroll", "click", "click_text", "press_key", "type"):
                    view["offset"] = 0 if action in ("goto", "click", "click_text") else view["offset"]
                await execute(page, cmd)
            fails = 0
            last_failed = False
            params = {k: v for k, v in cmd.items() if k not in ("action", "reason", "todo")}
            history.append(f"{len(history) + 1}. {action} {json.dumps(params, ensure_ascii=False)} ({reason})")
        except Exception as e:
            fails += 1
            last_failed = True
            last_error = f"action '{action}' failed: {e}"
            log(f"  {last_error}")
            history.append(f"{len(history) + 1}. {action} FAILED: {str(e)[:80]}")
            if fails >= MAX_CONSECUTIVE_FAILS:
                return None, last_error
        log(f"  step {step} took {time.time() - step_started:.1f}s")

    return None, f"step limit ({MAX_STEPS}) reached"


async def main():
    if len(sys.argv) < 3:
        print("Error: Missing execution runtime parameters.")
        return

    try:
        open(LOG_FILE, "w").close()
    except Exception:
        pass

    query = sys.argv[1]
    api_keys = [k.strip() for k in sys.argv[2].split(",") if k.strip()]
    if not api_keys:
        print("Error: No API keys provided to Sandbox.")
        return

    log(f"Task: {query} | keys: {len(api_keys)}")
    pool = KeyPool(api_keys)
    log(f"Config: model={pool.model} thinking={pool.think}/{THINKING_LEVEL} timeout={CALL_TIMEOUT_MS}ms "
        f"text_first={TEXT_FIRST} plan_memory={PLAN_MEMORY}")

    async with async_playwright() as p:
        log("Launching browser on virtual screen :99 ...")
        context = await p.chromium.launch_persistent_context(
            "/app/agent_scripts/google_user_profile",
            headless=False,
            viewport={"width": VIEW_W, "height": VIEW_H},
            args=[
                '--no-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu',
                '--disable-blink-features=AutomationControlled'
            ],
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        )
        page = context.pages[0] if context.pages else await context.new_page()

        try:
            await page.goto("https://www.google.com")
        except Exception as e:
            log(f"Initial navigation problem (continuing): {e}")
        await asyncio.sleep(3)

        result, reason = await agent_loop(context, page, query, pool)

        if result:
            log("Finished with a report.")
            print(result)
        else:
            log(f"Stopped without a report: {reason}")
            print(f"The visual agent stopped before finishing. Reason: {reason}")

        await asyncio.sleep(2)
        await context.close()


if __name__ == "__main__":
    asyncio.run(main())
