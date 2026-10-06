const DECISION_LABELS = {
  approved: "Approved",
  review_required: "Review Required",
  blocked: "Blocked",
};

const DECISION_CLASS = {
  approved: "badge badge-approved",
  review_required: "badge badge-review",
  blocked: "badge badge-blocked",
};

function DeploymentDecisionCard({ decision }) {
  if (!decision) return null;

  return (
    <section className="dashboard-section">
      <h2>Deployment Decision for This Scan</h2>
      <div className="deployment-decision-card">
        <span className={DECISION_CLASS[decision.decision] || "badge"}>
          {DECISION_LABELS[decision.decision] || decision.decision}
        </span>
        <p>{decision.reason}</p>
        {decision.failed_checks && decision.failed_checks.length > 0 && (
          <p className="hint">Failed checks: {decision.failed_checks.join(", ")}</p>
        )}
      </div>
    </section>
  );
}

export default DeploymentDecisionCard;
