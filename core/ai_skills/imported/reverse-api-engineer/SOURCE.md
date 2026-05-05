# Source — reverse-api-engineer

- **Upstream:** https://github.com/kalil0321/reverse-api-engineer
- **Imported on:** 2026-05-04
- **Files imported:** 13 (prompts + 3 reference Python interfaces + READMEs)
- **NOT imported as runtime code** — these files are design references.

## Why this was imported

Our `utils/har_analyzer.py` reads a HAR file and extracts API endpoints.
This repo goes further:

1. **Live browser API capture via Chrome native messaging host**
   (`native_host.py`) — captures requests in real time as the user
   interacts with the target, not from a static HAR.

2. **LLM-driven API client generation** (`auto_engineer.py`) — uses
   Claude SDK + MCP browser automation to autonomously explore an API
   and emit a typed Python client with documentation.

3. **Playwright codegen integration** (`playwright_codegen.py`) — turns
   captured interactions into runnable Playwright scripts (useful for
   reproducing complex multi-step exploits).

This is a real capability gap in our scanner.

## How to use in cyberm4fia-scanner

Reference imports — design inputs for these planned extensions:

- `utils/har_analyzer.py` could grow a `live_capture` mode using the
  native-host pattern from `interfaces/native_host.py`
- The `auto_engineer.py` prompt structure is a strong template for the
  scanner's `utils/ai_intent_agent.py` API-fingerprinting flow
- The Playwright codegen pattern can feed `utils/poc_generator.py` for
  multi-step exploit reproduction

These follow-ups are **not done yet** — ranked todo work.

## License

See upstream repository for license terms.
