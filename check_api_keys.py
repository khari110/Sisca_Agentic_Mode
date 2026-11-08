"""
check_api_keys.py

Standalone diagnostic tool for Sisca AI's api_key.txt / groq_api_key.txt.

Tests EVERY key individually against the real API with a tiny request,
and reports one of three verdicts per key:

  WORKING          -> key is valid and has quota left right now
  QUOTA_EXCEEDED   -> key is valid but today's free-tier quota is used up
  INVALID_KEY      -> key is malformed / not a real API key for this service

Run this on your local machine / server (NOT inside the sandbox container),
in the same folder as your Sisca_Agentic_Mode project:

    pip install google-genai groq --break-system-packages   # if not already installed
    python check_api_keys.py

It does NOT print full key values to the console (only a masked prefix/suffix),
so it's safe to paste the output back for debugging without leaking secrets.
"""

import os
import sys
import time

def mask(key: str) -> str:
    if len(key) <= 10:
        return key[:2] + "..." + key[-2:]
    return key[:6] + "..." + key[-4:]

def load_lines(path):
    if not os.path.exists(path):
        print(f"  (file not found: {path})")
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f.readlines() if line.strip()]

def check_gemini_keys():
    print("\n=== GEMINI KEYS (api_key.txt) ===")
    try:
        from google import genai
        try:
            import importlib.metadata as _im
            print(f"(installed google-genai SDK version: {_im.version('google-genai')})")
        except Exception:
            pass
    except ImportError:
        print("google-genai not installed. Run: pip install google-genai --break-system-packages")
        return

    keys = load_lines("api_key.txt")
    if not keys:
        print("No keys found in api_key.txt")
        return

    results = []
    for i, key in enumerate(keys, start=1):
        key_type = "Auth key (AQ.)" if key.startswith("AQ.") else \
                   "Standard key (AIza)" if key.startswith("AIza") else "Unrecognized format"
        label = f"Key #{i} ({mask(key)}) [{key_type}]"

        try:
            client = genai.Client(api_key=key)
            response = client.models.generate_content(
                model="gemini-3.8-flash",
                contents="Reply with just the word OK.",
            )
            _ = response.text  # force evaluation
            print(f"{label}: WORKING ✅  (quota available right now)")
            results.append((label, "WORKING"))
        except Exception as e:
            err = str(e).lower()
            if "429" in err or "resource_exhausted" in err or "quota" in err:
                print(f"{label}: QUOTA_EXCEEDED ⏳  (valid key, today's free-tier limit used up)")
                results.append((label, "QUOTA_EXCEEDED"))
            elif ("401" in err or "403" in err or "oauth" in err or
                  "access_token_type_unsupported" in err or "unauthenticated" in err):
                print(f"{label}: AUTH_TRANSPORT_ISSUE ⚠️  ({str(e)[:150]})\n"
                      f"   -> This looks like the AIza->AQ key migration friction Google is "
                      f"currently rolling out, not necessarily a dead/wrong key. Try upgrading: "
                      f"pip install -U google-genai --break-system-packages")
                results.append((label, "AUTH_TRANSPORT_ISSUE"))
            elif "api key not valid" in err or "api_key_invalid" in err or "400" in err or "permission" in err:
                print(f"{label}: INVALID_KEY ❌  ({str(e)[:120]})")
                results.append((label, "INVALID_KEY"))
            else:
                print(f"{label}: UNKNOWN_ERROR ⚠️  ({str(e)[:150]})")
                results.append((label, "UNKNOWN_ERROR"))

        time.sleep(1) 

    working = sum(1 for _, s in results if s == "WORKING")
    print(f"\nSummary: {working}/{len(results)} Gemini keys are usable right now.")

def check_groq_keys():
    print("\n=== GROQ KEYS (groq_api_key.txt) ===")
    try:
        from groq import Groq
    except ImportError:
        print("groq not installed. Run: pip install groq --break-system-packages")
        return

    keys = load_lines("groq_api_key.txt")
    if not keys:
        print("No keys found in groq_api_key.txt")
        return

    for i, key in enumerate(keys, start=1):
        label = f"Groq Key #{i} ({mask(key)})"
        try:
            client = Groq(api_key=key)
            completion = client.chat.completions.create(
                model="openai/gpt-oss-120b",
                messages=[{"role": "user", "content": "Reply with just OK."}],
            )
            _ = completion.choices[0].message.content
            print(f"{label}: WORKING ✅")
        except Exception as e:
            err = str(e).lower()
            if "429" in err or "rate" in err or "quota" in err:
                print(f"{label}: QUOTA/RATE_LIMITED ⏳  ({str(e)[:120]})")
            else:
                print(f"{label}: ERROR ❌  ({str(e)[:150]})")
        time.sleep(1)

if __name__ == "__main__":
    print("Sisca AI - API Key Diagnostic Tool")
    print("Testing each key individually against the live API...\n")
    check_gemini_keys()
    check_groq_keys()
    print("\nDone. Keys marked WRONG_FORMAT should be deleted from api_key.txt - "
          "they are not valid Gemini keys and will always fail, wasting a rotation slot.")
