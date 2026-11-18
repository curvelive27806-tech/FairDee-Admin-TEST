# Security Specification & Red-Team TDD Matrix

## Data Invariants
1. **Admin & Owner Authority Isolation**: Only verified admin accounts (`curvelive27806@gmail.com` or UIDs registered in `/admins/{uid}`) may create, edit, approve, revoke approval, or delete `/packages/{packageId}`. Only the System Owner (`curvelive27806@gmail.com`) may invite admins, promote a member to `'admin'`, revoke `'admin'` privileges, or modify admin status/grants (`/admins/{uid}`).
2. **Server-Side Separate Role Quotas (200 Agents / 10 Admins)**:
   - `/system/memberQuotas` maintains `{ activeAgentCount, activeAdminCount, ownerEmail, updatedAt }`.
   - `activeAgentCount` counts ONLY `role == 'agent' && status == 'approved'` (never `pending`, `suspended`, or `rejected`) and MUST NEVER exceed `200`.
   - `activeAdminCount` counts ONLY `role == 'admin' && status == 'approved'` (including System Owner) and MUST NEVER exceed `10`.
   - Any concurrent approval or reactivation that attempts to push `activeAgentCount > 200` or `activeAdminCount > 10` is atomically rejected via Firestore `runTransaction` + `getAfter(/system/memberQuotas)` Security Rules.
3. **Broker Read Boundary (Approved-Only Server Gate)**: Signed-in non-admin users (`isSignedIn()`) may read/list `/packages/{packageId}` ONLY when `resource.data.status == 'approved'`. Draft/imported (`pending`) and `expired` packages are rejected at the Firestore rule layer.
4. **Self-Assigned Privilege Prevention**: General registration on `/members/{uid}` MUST have `role == 'agent'`, `status == 'pending'`, `fmVerified == false`, and `authUid == request.auth.uid`. Users cannot elevate their own `role` or `status`.
5. **Strict Payload Keys & Bounds**: Every document write passes `isValid[Entity](incoming())` enforcing `keys().hasAll(...)` + `keys().hasOnly(...)`, type validation, and `.size()` caps on every string field.
6. **Temporal Integrity & Immutable Creation Metadata**: `createdAt == request.time` on create; `createdAt == existing().createdAt` and `updatedAt == request.time` on update.

## Dirty Dozen Adversarial Payloads (Expected: `PERMISSION_DENIED`)
1. **Unauthenticated List Packages**: `auth: null`, `list('/packages')` -> Rejected by `isSignedIn()`.
2. **Unverified Email Spoofing Admin**: `auth: { uid: 'x', token: { email: 'curvelive27806@gmail.com', email_verified: false } }`, `create('/packages/p1')` -> Rejected by `email_verified == true`.
3. **Broker Querying Pending Packages**: `auth: brokerUid (verified)`, `list('/packages', where status == 'pending')` -> Rejected by `resource.data.status == 'approved'`.
4. **Broker Getting Unapproved Package by Direct ID**: `auth: brokerUid`, `get('/packages/pending-id')` -> Rejected by `existing().status == 'approved'`.
5. **Broker Approving a Package**: `auth: brokerUid`, `update('/packages/p1', { status: 'approved' })` -> Rejected by `isAdmin()`.
6. **Broker Self-Escalating Member Role to Admin**: `auth: brokerUid`, `create('/members/brokerUid', { role: 'admin', status: 'approved' })` -> Rejected (`role == 'agent' && status == 'pending'`).
7. **Broker Self-Approving Pending Member Profile**: `auth: brokerUid`, `update('/members/brokerUid', { status: 'approved' })` -> Rejected by `affectedKeys().hasOnly(['fullName', 'phone', 'fmCode', 'updatedAt'])`.
8. **Non-Owner Admin Inviting or Revoking Another Admin**: `auth: nonOwnerAdmin`, `create('/admins/otherUid')` or `update('/members/target', { role: 'admin' })` -> Rejected by `isOwnerAdmin()`.
9. **201st Broker Approval Overflow**: `update('/members/agent201', { status: 'approved' })` when `activeAgentCount == 200` -> Rejected by `quotaAfter().activeAgentCount <= 200` & atomic counter check.
10. **11th Admin Invitation / Reactivation Overflow**: `create('/members/admin11', { role: 'admin', status: 'approved' })` when `activeAdminCount == 10` -> Rejected by `quotaAfter().activeAdminCount <= 10`.
11. **Backdated/Forged Server Timestamp**: `auth: adminUid`, `create('/packages/p1', { createdAt: clientTimestamp })` -> Rejected by `createdAt == request.time`.
12. **Reading Another User's PII Member Record**: `auth: brokerA`, `get('/members/brokerB')` -> Rejected by PII isolation (`authUid == request.auth.uid || email == request.auth.token.email || isAdmin()`).
