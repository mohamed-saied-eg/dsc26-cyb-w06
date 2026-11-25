## Tools

- Claude (Anthropic): used as a step-by-step guide for writing normalize.py, prompt.py and output.py.
- uv, Python 3.12, pytest, git, GitHub, VS Code.

## What AI got wrong

- It guessed the name of the DSC GitHub organisation (DSC-Egypt) without knowing it, and the link was not verified.
- When I printed normalize.py in the Windows terminal, the hidden characters and Arabic text were shown garbled, so the code had to be rewritten with \u escape sequences instead of copying the characters.

## In my own words

1. Stripping Markdown images removes the exfiltration leg of the lethal trifecta. This is critical for Hisn because private data and untrusted input are unavoidable for the system to work, so blocking silent data leaks (auto-loaded image URLs) is the only way to break the attack chain.

2. Triage escalates severity when an injection attempt is detected because we can no longer trust a "low" or "benign" rating from the model, as it might have been tricked into downplaying a real threat. A simple warning could easily be missed during off-hours, whereas escalating the severity guarantees that a human analyst will actually review the alert.