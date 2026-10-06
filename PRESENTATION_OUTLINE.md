# Presentation Outline

A suggested structure for a 12-15 minute academic presentation, roughly one slide per bullet group below. Pair with `DEMONSTRATION_SCRIPT.md` for the live-demo portion (Slides 9-11).

## Slide 1: Title
- Project title, team member names, course/institution, date.

## Slide 2: The Problem
- Security scanners produce large, differently-formatted reports.
- No aggregation, no prioritization, no connection to a deployment decision, no explainability.
- The question every team needs answered before deploying: *is this build safe to ship?* - currently answered manually and inconsistently.

## Slide 3: Project Objectives
- Bullet the 9 objectives from `PROJECT_REPORT.md` Section 3, or condense to the top 4-5.

## Slide 4: System Architecture
- Show the architecture diagram from `PROJECT_REPORT.md` Section 5 (or `README.md`).
- Walk through the flow left to right: push → scan → process → predict → explain → decide → dashboard/deploy.

## Slide 5: Technology Stack
- One slide, grouped by layer (CI/CD, backend, ML/XAI, frontend, cloud) - table from Section 6.

## Slide 6: Team Responsibilities
- From Phase 1's planning document: DevSecOps/Cloud, ML/XAI, Backend/Frontend.

## Slide 7: Machine Learning Approach
- Why synthetic data (no public labeled dataset exists for this problem) - state this plainly, it's a strength of the presentation to be upfront about it, not a weakness to hide.
- Random Forest, 11 features, 3-class target.
- Show the real evaluation table (accuracy 81.5%, per-class precision/recall/F1) and the honest note about weaker High-class recall.

## Slide 8: Explainable AI
- SHAP for the trained model; rule-based breakdown fallback when no model is available - and why the two are never confused with each other.
- Show one real example explanation (Section 11 of the report).

## Slide 9-11: Live Demonstration
- Follow `DEMONSTRATION_SCRIPT.md` exactly. Three scenarios: Low-risk (approved), High-risk (blocked), Remediation (approved again) - shown on the actual dashboard.

## Slide 12: Deployment Decision Policy
- The three rules, in the order they're actually evaluated: invalid prediction → blocked; mandatory check failure → blocked regardless of risk; otherwise Low/Medium/High → approved/review/blocked.
- Emphasize: this is enforced *structurally* in the CI/CD pipeline (a failed gate job cannot let deployment proceed), not just as application logic.

## Slide 13: AWS Deployment & CI/CD
- Diagram: build-test-scan → build-and-push-images + deployment-gate → deploy (gated by GitHub Environment approval for Medium risk).
- PostgreSQL never publicly exposed - security group + Docker binding, shown together.

## Slide 14: Testing
- 113 automated tests: 74 unit / 16 integration / 23 end-to-end.
- The three demonstration scenarios are themselves automated, repeatable tests, not just a manual walkthrough.

## Slide 15: Limitations & Future Work
- 3-4 limitations from Section 13, honestly stated.
- 3-4 future enhancements from Section 14.

## Slide 16: Conclusion
- One sentence restating what was built and verified.
- Thank you / questions.

---

**Presentation tips:**
- Lead with the live dashboard early if time is tight - a working system is more convincing than slides describing one.
- Have the model evaluation numbers memorized (81.5% accuracy, 0.381 recall on High) - a question about "how good is your model" is likely, and the honest, specific answer is stronger than a vague one.
- If asked "why not use a real dataset," the answer is direct: no such labeled dataset exists publicly, because it would require proprietary incident data organizations don't publish - this is explained in the report, not a gap in preparation.
