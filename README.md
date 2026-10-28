# Microsoft 365 Operational Hardening

Follow the phases in order. Complete the emergency-access prerequisite before running the Phase 1 hardening script.

## 1. Prerequisite: emergency access accounts and exclusions

1. Create and test at least two emergency access (break-glass) accounts in the tenant.
2. Record and verify each account's Entra object ID.
3. Before creating or enforcing Conditional Access policies, ensure these accounts are excluded from existing policies. Phase 1 also excludes the configured account IDs from the policies it creates.
4. Replace the sample emergency account IDs with the verified IDs in both `pre-requisite/pre-requisite.ps1` and `phase1/Set-M365SecurityControls.ps1.ps1`.
5. Run the prerequisite check from the repository root:

   ```powershell
   .\pre-requisite\pre-requisite.ps1
   ```

   This script checks that at least two account IDs are declared; it does not create accounts or verify policy exclusions. Complete those steps manually before continuing.

## 2. Phase 1: run hardening and review results

Run the Phase 1 script from the repository root:

```powershell
.\phase1\Set-M365SecurityControls.ps1.ps1
```

The script connects to Microsoft Graph and Microsoft Teams and creates or updates security controls. Review the results and verify the outcome for your tenant using the saved result files:

- `phase1/hardening-results.txt.txt`
- `phase1/hardening-results-with-exclusionId.txt`

The saved files are reference results; running the script does not automatically refresh these files. Verify the live tenant results after the run. Resolve unexpected results before proceeding.

## 3. Phase 2: review the solution

Read [`phase2/solution.md`](phase2/solution.md) for the hardening solution, rationale, and rollout guidance.
