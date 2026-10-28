# Contributing

1. Branch from `main` and open a pull request; `main` only changes through PRs.
2. Read AGENTS.md (project rules) and docs/PARITY_WORKFLOW.md (how parity work
   is done and measured).
3. Provision the pinned dependency graphs once, as described in VERIFICATION.md.
4. Before requesting review, run the full gate locally:

   ```sh
   python3 tools/check.py
   ```

   There is no hosted CI (docs/CI.md), so the PR checklist records the local
   result.
5. Prefer squash merges; branches are deleted after merge.
