# Presentation guide — MCP Security Scanner

Bar David and Noam Ben Lulu · Technion · B.Sc. Electrical and Computer Engineering

## Seven-minute walkthrough

1. **Problem (one minute).** MCP connects an assistant to tools. Both implementation code and tool descriptions can introduce risk. This project statically scans source, configuration, and dependency artifacts. It uses rules and bounded data-flow analysis; these experiments improve rules, not model weights.
2. **Normal tool (one minute).** Run `python presentation_demo.py` and open `deliverables/Demo.html`. Show the addition tool. Explain that the tool code is parsed, never executed.
3. **Poisoned metadata (one minute).** Advance to step 2. The arithmetic is identical, but the description now directs the assistant to ignore prior instructions. Point to the stable MCP03 rule ID, location, and evidence.
4. **Remediation (one minute).** Advance to step 3. Explain dry run, backup, syntax validation, second scan, and idempotence. Only high-confidence MCP03/MCP06 cases are automatically editable. The demonstration actually performs the change on a disposable copy.
5. **Code flow (one minute).** Compare steps 4 and 5. Tool input enters a shell string versus an argument list with a fixed executable. The comparison selects MCP05. Other categories can remain; do not describe the second snippet as universally safe.
6. **Evaluation (one minute).** Open `Final_Validation_Report.html`. Show baseline and repaired development results separately from the one-shot final reserve. Explain precision = TP/(TP+FP), recall = TP/(TP+FN). A missed attack reduces recall even when precision is 100%.
7. **Limits (one minute).** Findings are evidence, not exploit proofs. Synthetic variants are related cases. The final reserve covers eight categories, not all sixteen. Assistant-created labels need independent human review. Present remaining failures openly.

## Reproducibility and fallback

The demo requires Python and this repository, with no optional packages, MCP SDK installation, credentials, or network. All target code is inert. The generated HTML is a recording of an actual local run; it is a fallback if a terminal presentation fails. Regenerate it with `python presentation_demo.py` to show current behavior. Arrow keys or Next/Previous navigate the HTML; browser Print exports all steps.

For a live CLI view, run `python -m mcp_scanner scan tests/samples/clean_server.py`, then `python -m mcp_scanner scan tests/samples/vulnerable_tool_poisoning.py --check MCP03 -v`. Findings normally return exit code 1; that is not a crash.

Do not rerun the final holdout during the presentation. Its results, actual code snapshot, hashes, and consumed marker document the completed experiment.
