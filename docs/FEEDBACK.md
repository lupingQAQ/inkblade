# Trial feedback

Thank you for trying InkBlade. Two kinds of feedback matter most:

1. **It broke** - installation, demo, reports, container, chart.
2. **It was wrong** - a finding that is not real, or a real issue it missed.

Both are welcome. Security issues are handled privately, not here
(see [../SECURITY.md](../SECURITY.md)).

---

## Where to send it

| Channel | Use for |
|---|---|
| GitHub issue (`bug` / `feature` template) | reproducible defects, missing capabilities |
| Private vulnerability report (Security -> Advisories) | anything security-relevant in InkBlade itself |
| Your pilot report + this form | structured evaluation, procurement evidence |

If you are evaluating under NDA, send this form through your existing channel and
redact hostnames/client names. We do not need your cluster identity to fix a bug.

---

## Copy this form

```markdown
### Environment

- InkBlade version (inkblade trial output `version:`): 
- Install method: pip -e / wheel / docker / helm
- OS + version: 
- Python: 
- Container runtime / Kubernetes (if used): 

### What I ran

- Command(s):
- Output directory:
- `inkblade doctor --mode mock --json` result (paste or attach):

### First-run result

- [ ] `inkblade trial` completed
- [ ] all expected artifacts present
- [ ] report readable and plausible
- [ ] static UI opened
- [ ] demo credentials worked

Time to first successful run (minutes): 

### What surprised me

(one paragraph, plain language - this is the most useful part)

### Defects

| # | Step to reproduce | Expected | Actual | Severity |
|---|---|---|---|---|
| 1 | | | | blocker / major / minor |

Attach logs (`*.log`), `reports/trial-report.json`, and screenshots.

### Coverage and correctness (pilot only)

- Profile used: 
- Modules executed: 
- Findings confirmed / refuted: 
- Known true issues missed: 
- FP/FN table attached: yes / no
- Metrics table attached (see docs/PILOT-KIT.md section 4): yes / no

### Adoption

| Question | Answer |
|---|---|
| Would you run this again on another cluster? | yes / no / conditions |
| What blocks production use today? | |
| Which single feature would change the decision? | |
| Are you willing to be a reference customer? | yes / anonymized / no |

### Permissions

- [ ] I agree that this feedback may be used to improve InkBlade
- [ ] I agree that an anonymized quote may be published
- [ ] Keep this feedback private
```

---

## Triage commitments

| Input | First response | Resolution target |
|---|---|---|
| Blocker (install/demo cannot complete) | 2 business days | 10 business days |
| Major (wrong output, missing artifact) | 3 business days | next minor release |
| Minor / cosmetic | 10 business days | batched |
| Feature request | 10 business days (accept/decline + reason) | roadmap, not committed |
| Covered by an existing issue | same day, with link | - |

Every accepted defect gets a regression test before the fix ships. Feedback that
identifies a **false positive** is turned into a fixture case, and a **false
negative** into a module or applicability entry - that is how the corpus grows.

---

## What we do with the data

* Feedback is stored in the project tracker, not in the public tree.
* Hostnames, IPs, cluster identifiers and client names are stripped before
  anything is quoted publicly.
* Attachments containing evidence are deleted after triage unless you ask us to
  keep them.
* We never contact your infrastructure to reproduce a report. If reproduction
  needs a lab, we build it from your sanitized description.

---

## Honest disclosure of limitations

Things that are known and do not need a report:

* the mock demo is synthetic and proves pipeline behaviour only;
* CVE coverage is a curated registry, not a full vulnerability database
  (see `docs/SOTA-2026-10.md` for the current matrix);
* `static-only` registry entries are not exploitable without the full stack and
  are excluded from verified counts on purpose;
* managed control planes hide node/kubelet surfaces - coverage is reported
  accordingly, not silently dropped;
* Windows console codepage can garble CJK output; `PYTHONIOENCODING=utf-8` fixes
  it.

Anything else that looks wrong is worth reporting.
