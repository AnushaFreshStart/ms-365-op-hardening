Here is the recommended and prioritized security control roadmap tailored for a small-to-medium business with 100 users, 2 IT administrators, and Microsoft 365 licensing. 

With limited IT administrative capacity, the deployment strategy prioritizes **high-impact blast-radius reduction**, **automated threat remediation**, and **low-overhead maintenance** while avoiding accidental administrative lockouts.

---

### **1. Enforce Phishing-Resistant MFA for Administrative Roles (`CA001`)**

* **Why It Matters & Risk Mitigated:** 
  Administrators possess elevated permissions to alter tenant identities, applications, security policies, and roles. A compromised administrative account carries a severe blast radius. Standard MFA methods (SMS, voice calls, push notifications) remain vulnerable to social engineering, adversary-in-the-middle (AiTM) relay phishing, and push fatigue. Requiring **Phishing-resistant MFA** (FIDO2 security keys, Fast Identity Online v2 passkeys, or Windows Hello for Business) cryptographically binds authentication to Microsoft Entra ID, completely neutralizing credential theft and relay attacks.

* **Rollout Strategy for Limited Admin Resources (2 Admins):**
  1. **Prepare Safety Controls:** Before creating policies, set up two cloud-only emergency access (**break-glass**) Global Administrator accounts that are explicitly excluded from baseline Conditional Access policies to prevent tenant lockout. Store their credentials in physical custody and configure high-priority sign-in alerts.
  2. **Role Targeting:** Target the policy using directory role templates (`includeRoles`) for all administrative roles rather than maintaining manual groups.
  3. **Staged Enforcement:** Deploy the policy in **Report-only mode** (`enabledForReportingButNotEnforced`), validate via the What-If evaluation tool and sign-in logs, confirm hardware FIDO2 registration for both admins, and then switch state to **On** (`enabled`).

* **Drawbacks & Trade-offs:** 
  Requires hardware preparation (FIDO2 passkey provisioning) prior to enforcement. Mismanaging exclusions or enabling enforcement before hardware method registration risks locking administrators out of tenant management.

---

### **2. Block Legacy Authentication Protocols (`CA003`)**

* **Why It Matters & Risk Mitigated:** 
  Outdated authentication protocols (such as Exchange ActiveSync, POP3, IMAP4, and basic credential scripts) cannot execute modern authentication checks like MFA or device compliance claims. Consequently, password spray, credential stuffing, and brute-force attacks overwhelmingly target legacy endpoints.

* **Rollout Strategy for Limited Admin Resources (2 Admins):**
  1. **Audit Traffic:** Filter Microsoft Entra sign-in logs by `Client App` over a full 30-day business cycle to identify legacy client connections across interactive and non-interactive traffic.
  2. **Remediate Dependencies:** Upgrade legacy Office clients, modernise mail apps, and transition automated scripts to managed identities or service principals.
  3. **Targeted Block Policy:** Configure a Conditional Access policy scoping `All users` across `All resources`, selecting client app conditions for `exchangeActiveSync` and `other`. Deploy in **Report-only mode** to verify that no critical background jobs trigger a "Would block" status before enforcing.

* **Drawbacks & Trade-offs:** 
  Older legacy software, legacy multi-function printer scanners, or unmonitored background scripts relying on basic authentication will fail to authenticate until upgraded or reconfigured with modern authentication.

---

### **3. Enforce Universal MFA for All Users (`CA002`)**

* **Why It Matters & Risk Mitigated:** 
  Standard user accounts hold access to sensitive corporate mail, files, and internal communications. Passwords alone are highly vulnerable to phishing, reuse, and disclosure. Enforcing universal MFA drastically reduces account compromise across the 100-user population.

* **Rollout Strategy for Limited Admin Resources (2 Admins):**
  1. **Readiness Audit:** Use authentication method registration reporting (`Get-MgReportAuthenticationMethodUserRegistrationDetail`) to identify users who lack registered MFA methods.
  2. **Automated Onboarding:** Issue registration communications and Temporary Access Passes (TAP) to unprepared employees to avoid direct helpdesk burden.
  3. **Policy Scope:** Scope the policy to `All users` and `All resources` using the built-in **Multifactor authentication** strength (`00000000-0000-0000-0000-000000000002`), while keeping break-glass accounts excluded. Expand enforcement in controlled pilot waves before enabling globally.

* **Drawbacks & Trade-offs:** 
  Introduces minor sign-in friction during initial onboarding. Users who fail to register required methods prior to enforcement will be blocked at sign-in, creating temporary support tickets for the 2 IT admins.

---

### **4. Deploy Risk-Based Sign-In & User Risk Policies (`CA004` & `CA005`)**

* **Why It Matters & Risk Mitigated:** 
  Microsoft Entra ID Protection evaluates real-time sign-in risk (e.g., unfamiliar sign-in properties, anonymous IP addresses) and cumulative user risk (e.g., leaked credentials traded on the dark web). `CA004` challenges Medium and High sign-in risks with fresh MFA, while `CA005` forces High-risk users into automated remediation.

* **Rollout Strategy for Limited Admin Resources (2 Admins):**
  1. **Separate Risk Policies:** Keep sign-in risk (`CA004`) separate from user risk (`CA005`) to maintain predictable remediation flows and simplified reporting.
  2. **Self-Service Remediation:** Pair `CA005` with **Self-Service Password Reset (SSPR)** set to **All** users and password writeback enabled. This allows compromised users to self-remediate by performing MFA and a secure password change without calling the 2 IT admins.
  3. **Enforcement:** Configure sign-in risk to require MFA with **Sign-in frequency** set to **Every time**, ensuring session tokens cannot bypass active risk challenges.

* **Drawbacks & Trade-offs:** 
  Requires Microsoft Entra ID P2 or suite licensing. If a high-risk user has not pre-registered MFA or SSPR, their account will be blocked and require manual intervention by an admin.

---

### **5. Prevent Ungoverned Application Consent & Restrict Teams Meetings**

* **Why It Matters & Risk Mitigated:** 
  * **App Consent:** Consent phishing tricks standard users into granting third-party OAuth apps broad delegated access to corporate emails, OneDrive files, and contacts without revealing their password.
  * **Teams Meetings:** Unrestricted meeting defaults allow uninvited anonymous users or attendees to disrupt meetings, hijack screen sharing, or access sensitive discussions.

* **Rollout Strategy for Limited Admin Resources (2 Admins):**
  1. **App Consent Policy:** In Enterprise Applications, set User Consent to **Do not allow user consent**. Enable the **Admin Consent Workflow** so users can submit legitimate software requests to a centralized queue for the 2 admins to review.
  2. **Teams Baseline Policy:** Update the Global Teams meeting policy to enforce secure defaults across all organizers:
     * **Who can bypass the lobby:** Set to **People who were invited** (`InvitedUsers`).
     * **Who can present:** Set to **Only organizers and co-organizers** (`OrganizerOnlyUserOverride`).
     * **Anonymous join:** Turn **Anonymous users can join a meeting** to **Off** (`AllowAnonymousUsersToJoinMeeting = $false`).

* **Drawbacks & Trade-offs:** 
  * Disabling self-consent requires admins to evaluate app request permissions, publisher verification, and business justification. 
  * Restricting Teams presentation and anonymous join requires meeting organizers to manually promote guest presenters during calls or use dedicated policy exceptions for public webinars.

---

### **Summary Architecture & Ranking Comparison**

| Rank | Security Control | Target Risk | Primary Enforcement Tool | Admin Overhead |
| :--- | :--- | :--- | :--- | :--- |
| **1** | **Phishing-Resistant MFA (`CA001`)** | Privileged Account Takeover & AiTM Phishing | Conditional Access + FIDO2 / Passkeys | Low (after setup) |
| **2** | **Block Legacy Auth (`CA003`)** | Password Spray & Basic Auth Attacks | Conditional Access (`exchangeActiveSync`, `other`) | Very Low |
| **3** | **Universal All-User MFA (`CA002`)** | Credential Stuffing & User Phishing | Conditional Access + Registration Reporting | Moderate (onboarding) |
| **4** | **Risk-Based Protection (`CA004`/`CA005`)** | Anomaly & Leaked Credential Exploitation | Entra ID Protection + SSPR Self-Remediation | Low (self-service) |
| **5** | **App Consent & Teams Hardening** | Consent Phishing & Meeting Intrusion | Entra Auth Policy + Teams Global Policy | Low |

---
