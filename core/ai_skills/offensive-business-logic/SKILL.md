---
name: offensive-business-logic
description: "Business logic vulnerability testing — flaws in application workflow rather than a single injectable input. Covers price/quantity tampering, negative values, workflow/step skipping, race conditions on limited resources, coupon/refund abuse, and trust-boundary assumptions. Use when assessing checkout, payments, transfers, quotas, and multi-step flows."
---

# Business Logic Vulnerabilities — Offensive Testing Methodology

## Quick Workflow

1. Model the intended workflow and its invariants (what must always hold true)
2. Identify trust assumptions the server makes about client behavior
3. Violate each assumption: order, value range, repetition, timing
4. Measure real-world impact (money, data, quota)

---

## Common Classes

### Value / Parameter Tampering

- Negative quantity/price → credit instead of charge: `quantity=-5`
- Currency or decimal manipulation: `amount=0.001`, integer overflow
- Client-trusted totals: change `total=` while items stay the same
- Tamper IDs of products/tiers to buy premium at basic price

### Workflow / Step Skipping

- Jump straight to the confirmation/fulfilment step, skipping payment
- Reuse a one-time step token; replay a completed step
- Reorder multi-step flows (KYC, approval) to bypass a gate

### Quantity / Quota Abuse

- Apply the same coupon/gift card repeatedly
- Refund more than paid; cancel after fulfilment
- Exceed per-user limits via parallel requests (see race conditions)

### Race Conditions on Limited Resources

Submit concurrent requests against a check-then-act window:

- Redeem one coupon N times simultaneously
- Withdraw/transfer balance twice before it decrements
- Claim the last item more than once

(See offensive-race-condition for tooling — single-packet / last-byte sync.)

---

## Testing Tips

- Always compare what the client *can* send vs what the UI *does* send
- Replay requests out of intended order; drop "required" prerequisite calls
- Look for server reliance on hidden fields, referer, or step counters
- Chain with IDOR/mass-assignment to amplify impact

---

## Remediation

- Enforce all invariants server-side; never trust client-supplied prices/totals
- Validate value ranges (no negatives, sane maxima), recompute totals server-side
- Make state transitions server-authoritative; bind step tokens to session + order
- Use atomic transactions / locks / idempotency keys for limited resources
