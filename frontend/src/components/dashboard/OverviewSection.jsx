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

function StatCard({ label, value, sub }) {
  return (
    <div className="stat-card">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  );
}

function OverviewSection({ stats }) {
  if (!stats) return null;

  if (stats.total_scans === 0) {
    return (
      <section className="dashboard-section">
        <h2>Overview</h2>
        <p className="hint">
          No scans have been submitted for <strong>{stats.application_name}</strong> yet.
        </p>
      </section>
    );
  }

  return (
    <section className="dashboard-section">
      <h2>Overview</h2>
      <div className="stat-grid">
        <StatCard label="Total Scans" value={stats.total_scans} />
        <StatCard
          label="Critical / High Findings"
          value={`${stats.critical_count ?? 0} / ${stats.high_count ?? 0}`}
          sub="in latest scan"
        />
        <StatCard
          label="Latest Risk Score"
          value={stats.latest_risk_score != null ? stats.latest_risk_score.toFixed(1) : "-"}
          sub={stats.latest_risk_category || ""}
        />
        <div className="stat-card">
          <div className="stat-label">Deployment Status</div>
          <div className="stat-value">
            {stats.latest_deployment_decision ? (
              <span className={DECISION_CLASS[stats.latest_deployment_decision] || "badge"}>
                {DECISION_LABELS[stats.latest_deployment_decision] || stats.latest_deployment_decision}
              </span>
            ) : (
              "-"
            )}
          </div>
        </div>
      </div>
    </section>
  );
}

export default OverviewSection;
