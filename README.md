# llmsec

Small tool I wrote to test LLM-backed apps (chatbots, RAG, agents) for the usual problems:
prompt injection, system prompt leaks, credential/data leaks, tool abuse.
No dependencies, just python 3.9+.

Only run it against things you own or have permission to test.

## try it

    python demo/vuln_app.py &
    python -m llmsec --url http://127.0.0.1:8000 --authorized --known sk-acme

## real target

    python -m llmsec --url https://app.example.com/api/chat \
      --template '{"messages":[{"role":"user","content":"{{PROMPT}}"}]}' \
      --path choices.0.message.content \
      --header "Authorization: Bearer $TOKEN" --authorized

Each probe runs a couple of times with a fresh random canary, since models don't answer
the same way twice. The canary is split up in the prompt so an app that only echoes your
input doesn't count as a hit.

Output goes to `report.md` and `report.json`.

## todo

- multi-turn attacks
- rag poisoning (upload doc, ask about it later)
- sarif output
- llm judge instead of regexes
