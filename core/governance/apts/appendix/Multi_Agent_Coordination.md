# Multi-Agent Coordination

Informative Appendix (non-normative)

## Purpose and applicability

This appendix covers platforms that split an engagement across multiple agents, workers, or model-driven components. It does not create new conformance requirements. The purpose is narrower. APTS already includes controls for scope, safety, logging, containment, and human oversight. Most of those controls were written against a single agent runtime. Once a platform distributes work across several concurrent decision makers, the same control logic still applies, but the failure modes change.

That change matters. A platform can have a solid kill switch, clean scope validation, and a respectable audit trail when tested as a single-agent system, then fail under concurrent operation. One worker halts, another continues. Each worker stays inside its local rate budget, but the target still receives excessive traffic in aggregate. One agent treats a newly discovered asset as merely interesting; another treats the same discovery as implicit authorization to probe it. Those are recognizable multi-agent safety failures.

Primary scope: one platform or operator-controlled system running multiple workers, role-separated agents, or semi-independent decision components under one engagement authority and one coordination fabric.

Limited scope: semi-independent agents participating in one engagement while still operating under a shared coordination layer or shared operator authority model.

Out of scope for normative interpretation: truly independent agents from different vendors or separate control planes that merely happen to work on the same customer environment. In that case, many of the patterns below become coordination expectations or contractual practices rather than platform-enforced safeguards.

For this appendix, "multi-agent" should be read in two layers.

The primary case, and the one this appendix is written for, is a single platform or operator-controlled system running multiple concurrent workers, role-separated agents, or semi-independent decision components under one engagement authority. In that design, the platform owns the coordination fabric. It can enforce one halt state, one scope authority, one shared budget, and one audit model across all active components.

The secondary case is looser: multiple semi-independent agents participating in one engagement while still operating under a shared coordination layer or a shared operator authority model. That is harder to reason about, but the same control themes still apply if there is a genuine mechanism for shared halt, shared scope authority, and shared auditability.

The appendix is not written as a normative coordination model for truly independent agents from different vendors or separate control planes that merely happen to work on the same customer environment. Once the coordination fabric is split across separate operators, the problem changes. Internal platform controls can no longer be assumed to propagate, and many of the patterns below become interface expectations or contractual coordination practices rather than platform-enforced safeguards.

This appendix is mainly for:

- Platforms running multiple workers under one control plane
- Platforms using distinct planner, executor, verifier, reporter, or memory-management agents in one engagement
- Platforms coordinating semi-independent agents under a shared Rules of Engagement, scope definition, and operator authority model

If separate operators participate in one engagement, the guidance here is still useful, but it should be treated as a coordination baseline rather than proof that shared controls are actually enforced.

## Why multi-agent deployments need extra guidance

The issue is not that APTS lacks safety controls. The issue is that concurrency changes where those controls break.

In a single-agent design, most safety questions collapse into one runtime and one decision stream. In a multi-agent design, that is no longer true. There may be several planning contexts, several execution queues, several local memories, and several partial views of the same target. Coordination becomes part of the safety model whether the platform admits it or not.

The common failure cases are easy to recognize once you look for them:

- A halt signal stops one worker but reaches another too late
- Several agents each follow local rate limits while exceeding the engagement-wide budget together
- One agent forwards stale or poisoned state into another agent's working context
- Agent disagreement resolves quietly in favor of continued action because the timeout path was never designed
- Heartbeats show that every worker is alive, but one worker has already drifted into unsafe behavior

The rest of this appendix addresses those coordination failures by tying them back to existing APTS controls.

## Deployment models

### Shared control plane with parallel workers

One orchestration layer assigns work to multiple workers or agent instances. This is the most common model. The obvious risks are aggregate rate overshoot, uneven halt propagation, duplicate action against the same target, and shared-state corruption.

### Role-separated agent pipeline

Different agents or models play different roles: planner, executor, verifier, reporter, memory manager, and so on. Here the main problem is not raw concurrency. It is trust. A lower-trust component can influence a higher-impact one unless the handoff points are explicit and enforced.

### Semi-independent agents under one engagement authority

Several agents can make partially independent decisions while still operating under one Rules of Engagement document, one scope definition, one operator chain, and one audit model. This design can be workable. It can also fail in strange ways if disagreement handling is vague. The architecture has to answer a simple question: when two agents disagree about scope, impact, or authorization, who wins, and what happens in the meantime?

### Different vendors or different control planes

This case sits at the edge of the appendix rather than at its center. If two vendors, or two separately operated control planes, participate in one engagement, the internal coordination guarantees described elsewhere in this appendix may not exist. A shared kill state may be impossible. Shared rate budgets may be approximate. State isolation may be a legal or contractual concern rather than an internal architecture decision.

In that situation, the useful question is not whether the parties "support multi-agent operation" in the abstract. The useful question is whether they have a defined cross-operator coordination mechanism for halt, scope changes, budget enforcement, escalation, and audit evidence. If they do not, the safer assumption is that the engagement is a set of adjacent systems, not one coordinated multi-agent platform.

## Shared safety invariants

A useful review frame for multi-agent platforms is whether the architecture preserves a short set of invariants across every active worker and orchestration component.

- Scope remains centrally authoritative. Agents do not expand it by agreement among themselves.
- Safety controls remain binding even if one agent behaves unexpectedly, drifts, or is manipulated.
- Halt, pause, and containment decisions apply to the engagement as a whole, not just to the worker that noticed the problem.
- Shared coordination state is authoritative only when it lives outside any one agent runtime.
- Timeout, disagreement, or uncertainty never default to "proceed."
- Coordination logs make it possible to reconstruct who knew what, who decided what, and who acted when.

If those invariants do not hold during concurrent operation, the platform's existing controls may still exist individually, but the assurance value of those controls is reduced in practice.

## Distributed kill-switch propagation

In a multi-agent platform, a kill switch is a distributed control. That sounds obvious, yet this is where a lot of systems quietly fail. Stopping the worker that detected the incident is not enough. The halt has to reach every active worker before that worker dispatches its next action.

Practical designs usually rely on a shared halt signal outside the agent runtime. Some use publish-subscribe messaging. Some use a coordination gateway that invalidates every outstanding work item when the halt state flips. Some stamp each work lease with a halt epoch, then refuse dispatch when the epoch no longer matches. The exact mechanism matters less than the property it creates: once the halt state changes, no worker can continue acting because local state has not yet caught up.

The pre-invocation halt check from the issue discussion belongs here. It is one of the cleaner patterns because it catches the dangerous case: a worker that is still alive, still connected, and about to fire the next tool invocation after another part of the system has already decided the engagement must stop.

Reviewers should expect evidence that halt propagation is engagement-wide. The useful test is not whether one process can stop itself. The useful test is whether several active workers stop together, whether they stop before new actions are dispatched, and whether the audit trail shows when each worker observed and acknowledged the halt.

**Related normative requirements:** APTS-SC-009, APTS-HO-008, APTS-HO-009, APTS-HO-015, APTS-SC-018.

## Aggregate rate-limit coordination

Local compliance does not mean safe aggregate behavior. Three workers can each sit under their own request cap and still push the target past the engagement's allowed traffic budget.

The control that matters here usually sits above the workers. A gateway-enforced token bucket is a good example because it turns the budget into a shared scarce resource instead of a local promise. One worker spends tokens, which means fewer are available to the others. The same idea can be extended to bandwidth ceilings, payload-size limits, expensive action classes, and cooldown windows for fragile targets.

This control is easy to weaken by accident. Teams often implement "rate limiting" in each worker and call the job done. That misses the actual problem. In a multi-agent system, the safe question is not "did each worker stay polite?" It is "did the engagement as a whole stay within the allowed envelope?"

Reviewers should expect the platform to show where aggregate limits are enforced, how shared budgets are accounted for, and what happens when several workers compete for the same budget at once.

**Related normative requirements:** APTS-SC-004, APTS-SE-019, APTS-SC-006, APTS-SC-010.

## Intra-engagement scope conflict handling

Discovery is not authorization. In a multi-agent design, that distinction has to remain explicit.

One agent may discover a new host, a newly exposed admin path, or a credential that appears to open a second system. Another agent may be waiting for anything interesting to appear so it can continue the chain. That is exactly where scope errors happen. Shared knowledge starts to feel like shared permission.

The safer pattern is centralized re-validation. A newly discovered target, path, or credential can be shared as a candidate input, but another agent should not act on it until the authoritative scope logic has checked it. If the result is uncertain, the platform should escalate the uncertainty rather than let one agent inherit another agent's optimism.

This gets more important in overlapping or adjacent engagements. One worker may see an asset as familiar because it belongs to a different customer environment, a different campaign, or a previous engagement snapshot. The coordination layer has to distinguish "known to the platform" from "authorized for this engagement." Those are not the same thing.

Reviewers should expect the logs to show who discovered the candidate target, which control re-validated it, and whether the final decision was automatic or operator-driven.

**Related normative requirements:** APTS-SE-006, APTS-SE-007, APTS-SE-021, APTS-SE-022, APTS-HO-013.

## Agent state isolation

State isolation is one of the gaps the issue comments sharpened, and rightly so. Multi-agent systems fail in predictable but serious ways when working context moves across agent boundaries without controlled rules.

One agent's scratch notes should not become another agent's instructions by accident. A stale target classification should not linger in shared memory after the operator has changed the scope. A credential reference intended for a narrow path should not spread through several contexts just because it was convenient to replicate. These are not abstract concerns. They are how systems create their own cross-contamination.

The safer pattern is to isolate per-agent working memory and treat shared state as a separate, authoritative layer outside any one agent context. Scope, deny lists, operator directives, escalation state, approved credentials, and similar safety-critical facts belong there. Promotion from local state to shared state should be explicit. Shared facts should carry freshness markers or version identifiers so agents can tell whether the copy they are reading is still current.

There is also a role question. Not every agent should be able to write every class of shared state. A reporting agent does not need broad write authority over execution context. A verifier should not be able to silently rewrite the underlying evidence it is supposed to judge. The implementation details vary, but the principle is stable: convenient state sharing is not a safety property.

Reviewers should expect evidence that state sharing is intentional, role-bounded, and logged.

**Related normative requirements:** APTS-MR-022, APTS-MR-023, APTS-TP-017, APTS-AR-020, APTS-SE-023.

## Inter-agent communication trust boundaries

Agent-to-agent traffic should be treated as a real trust boundary, not as harmless internal chatter.

Messages can be stale. They can be malformed. They can relay target-controlled content dressed up as internal recommendation. They can carry scope references, identifiers, and credentials that look plausible enough to pass a casual check. The fact that a message came from another component inside the platform does not make it trustworthy.

The issue discussion pointed to authenticated messaging, and that belongs here. Session-scoped authentication is useful because it binds the message to the engagement and to the sending component. Message schemas help too, especially when they distinguish between observation, recommendation, request for approval, and execution result. Those categories matter. A platform gets into trouble when a descriptive message silently turns into an authorization signal.

There is a second boundary here as well: target-derived content relayed by one agent into another agent's context should stay classified as untrusted data. Internal routing does not cleanse it. If the first agent saw adversarial content, the second agent should not receive it as trusted instruction.

Reviewers should expect the platform to show how messages are authenticated, how message type is enforced, and which roles are allowed to trigger which downstream effects.

**Related normative requirements:** APTS-MR-018, APTS-MR-022, APTS-MR-023, APTS-SC-020, APTS-AR-020.

## Consensus, disagreement, and timeout-safe defaults

This is the other gap the comments pushed into focus. The safe default cannot be left implicit.

Multi-agent platforms often use verifier approval, planner-executor agreement, quorum, or paired review before a higher-impact action goes forward. That part is easy to describe on a diagram. The harder part is the failure path. What happens when one agent says the action is in scope and another flags uncertainty? What happens when the verifier does not answer? What happens when the containment check times out during a live decision window?

The answer should be restrictive. If the disagreement is safety-critical, the platform should pause, halt, or escalate. If a required approval path times out, the timeout should not count as implied consent. That was one of the clearest points in the issue discussion, and it should appear in the appendix exactly that way.

Not every disagreement needs the same treatment. An execution agent and a reporting agent may disagree on wording without any safety impact. That is fine. A dispute about scope, impact, authorization, or containment status is different. The platform should classify those as safety-critical and give them a defined restrictive fallback.

Reviewers should expect the platform to show both the normal consensus path and the timeout path. The timeout path is where systems reveal what they actually trust.

**Related normative requirements:** APTS-HO-003, APTS-HO-011, APTS-HO-012, APTS-SC-009, APTS-SC-018.

## Rogue agent detection and containment

Heartbeats are useful. They are not enough.

An agent can be fully alive from an infrastructure perspective while doing exactly the wrong thing. It may keep requesting blocked actions, probe the edges of scope repeatedly, drift into a role it was never supposed to hold, or produce action sequences that no sane operator would expect from its declared mandate. That is why the issue comments pushed behavioral anomaly detection over heartbeat-only checks.

The better pattern is to watch behavior, not just liveness. A platform can look for repeated blocked tool requests, strange parameter combinations, action distribution drift, conflict between local state and authoritative shared state, or role violations such as a reporting component trying to steer execution behavior. None of those signals need to be perfect in isolation. Taken together, they can show that one worker is no longer behaving like the worker the platform thinks it deployed.

Containment should be specific. If one agent drifts, the platform should be able to isolate or stop that agent, preserve its state and logs, and prevent it from dragging the rest of the engagement with it. Sometimes the right answer will still be a full halt. Sometimes it will be worker-level containment followed by operator review. The key point is that heartbeat status alone is too weak a proxy for safety.

**Related normative requirements:** APTS-MR-023, APTS-SE-026, APTS-SC-018, APTS-AL-028, APTS-AR-001.

## Coordination logging and reviewer evidence

By the time a reviewer reaches a multi-agent platform, the architecture diagram is rarely the hard part. The hard part is proving what happened during live coordination.

The audit record should let a reviewer answer basic but important questions:

- Which agents or workers were active during the engagement?
- What role did each one hold?
- Which component proposed, approved, rejected, or executed each significant action?
- What shared state or coordination message influenced that decision?
- When did halt, pause, escalation, or containment signals propagate?
- How did the platform handle disagreement, timeout, or anomalous behavior?

Useful evidence usually includes architecture diagrams, coordination-control design notes, kill-propagation test records, shared-budget enforcement evidence, state-isolation design, anomaly-detection workflow records, and incident or tabletop material showing how the platform handles one misbehaving agent in the presence of several healthy ones.

What matters is reconstructability. If a reviewer cannot tell which agent knew what and when it knew it, the platform may still have logs, but it does not yet have a coordination audit trail that can support serious review.

| Reviewer question | Evidence to request | Relevant APTS anchors |
|-------------------|---------------------|-----------------------|
| Does halt propagate across all active workers before new actions are dispatched? | Kill-switch test records, coordination logs, worker acknowledgment traces | APTS-SC-009, APTS-HO-008, APTS-HO-009 |
| Are rate and bandwidth limits enforced across the engagement rather than per worker only? | Shared-budget design, gateway enforcement records, concurrency test results | APTS-SC-004, APTS-SE-019, APTS-SC-006 |
| Is agent state isolated with controlled write paths into shared state? | State model documentation, role-based write controls, shared-state audit logs | APTS-MR-022, APTS-MR-023, APTS-AR-020 |
| What happens when agents disagree or a required approval path times out? | Decision-flow documentation, timeout-path test results, escalation records | APTS-HO-003, APTS-HO-011, APTS-HO-012 |
| Can the platform isolate one misbehaving agent without losing control of the engagement? | Containment drill records, anomaly-detection logic, incident review material | APTS-MR-023, APTS-SC-018, APTS-AL-028 |

**Related normative requirements:** APTS-AR-001, APTS-AR-020, APTS-HO-005, APTS-RP-004.

## Mapping to existing APTS requirements

| Coordination concern | Example implementation focus | Primary APTS anchors |
|----------------------|------------------------------|----------------------|
| Distributed halt across workers | Broadcast halt signal, pre-invocation halt check, halt acknowledgment tracking | APTS-SC-009, APTS-HO-008, APTS-HO-009, APTS-HO-015 |
| Aggregate impact and traffic control | Shared rate budget, gateway token bucket, central backoff enforcement | APTS-SC-004, APTS-SE-019, APTS-SC-006 |
| Scope conflict across agents | Re-validation of discovered assets, centralized scope adjudication | APTS-SE-006, APTS-SE-007, APTS-SE-021, APTS-HO-013 |
| Shared-state integrity | Authoritative external state store, controlled write paths, freshness markers | APTS-MR-022, APTS-MR-023, APTS-AR-020 |
| Inter-agent trust boundaries | Authenticated messaging, schema validation, role-bounded communication | APTS-MR-018, APTS-MR-022, APTS-SC-020 |
| Safe-default coordination decisions | Halt or pause on disagreement or timeout, escalation for unresolved decisions | APTS-HO-003, APTS-HO-011, APTS-HO-012 |
| Rogue agent handling | Behavioral anomaly detection, worker isolation, containment verification | APTS-MR-023, APTS-SC-018, APTS-AL-028 |
| Multi-agent audit reconstruction | Per-agent provenance, coordination event logs, state-transition records | APTS-AR-001, APTS-AR-020, APTS-RP-004 |

## Summary

Multi-agent operation does not replace the APTS control model. It raises the bar for how those controls have to be applied.

The platform still has to answer the same questions. What is in scope? What is allowed? What must stop immediately? Who approved the action? What happened, in what order, and why? A single-agent platform answers those questions through one decision stream. A multi-agent platform has to answer them across several concurrent ones without losing authority, clarity, or restraint. That is the standard this appendix is meant to support.
