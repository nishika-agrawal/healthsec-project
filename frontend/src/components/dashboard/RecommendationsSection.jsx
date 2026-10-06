const PRIORITY_CLASS = {
  CRITICAL: "badge badge-blocked",
  HIGH: "badge badge-review",
  MEDIUM: "badge",
  LOW: "badge",
};

function RecommendationsSection({ recommendations }) {
  if (!recommendations) return null;

  return (
    <section className="dashboard-section">
      <h2>Security Recommendations</h2>

      <p className="hint">
        {recommendations.critical_count} critical and {recommendations.high_count} high-severity
        finding(s) listed below. {recommendations.medium_noted} medium and{" "}
        {recommendations.low_noted} low-severity finding(s) were also found but are not
        individually listed.
      </p>

      {recommendations.recommendations.length === 0 ? (
        <p className="hint">No critical or high-severity findings require action right now.</p>
      ) : (
        <ul className="recommendation-list">
          {recommendations.recommendations.map((rec, index) => (
            <li key={index} className="recommendation-item">
              <div className="recommendation-header">
                <span className={PRIORITY_CLASS[rec.priority] || "badge"}>{rec.priority}</span>
                <span className="recommendation-category">{rec.category.replace(/_/g, " ")}</span>
              </div>
              <p className="recommendation-action">{rec.action}</p>
              <p className="recommendation-linked">
                Linked finding: {rec.linked_finding.identifier || "N/A"}
                {rec.linked_finding.component ? ` (${rec.linked_finding.component})` : ""}
              </p>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export default RecommendationsSection;
