"# ms-365-op-hardening" 

## Prerequisite: Conditional Access readiness

Complete this checklist before creating or enforcing Conditional Access policies. Do not proceed with enforcement until every applicable item is verified.

- [ ] Confirm the tenant and in-scope users have the licenses required for the planned Conditional Access features.
- [ ] Create and test at least two emergency access accounts. Exclude them from every Conditional Access policy and monitor their sign-ins.
- [ ] Inventory existing Conditional Access policies, users, groups, apps, devices, and locations; identify policy conflicts and dependencies.
- [ ] Verify in-scope users can satisfy the planned authentication requirements, including having registered the required authentication methods.
- [ ] Define a pilot group that includes representative users and use cases. Notify affected users and support teams.
- [ ] Record an owner and rollback plan, including how to disable the policy and verify access is restored.
- [ ] Plan to deploy new policies in report-only mode first, review sign-in results, and roll out enforcement in stages.

Record who completed the checks and when. Resolve any unmet prerequisite before proceeding; do not enforce a policy that could prevent administrators or users from accessing required resources."
