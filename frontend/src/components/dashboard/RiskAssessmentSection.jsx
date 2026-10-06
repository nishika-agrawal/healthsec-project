const CATEGORY_COLOR = {
  Low: "#16a34a",
  Medium: "#ca8a04",
  High: "#b91c1c",
};

function RiskAssessmentSection({ prediction }) {
  if (!prediction) return null;

  const scoreColor = CATEGORY_COLOR[prediction.risk_category] || "#6b7280";

  return (
    <section className="dashboard-section">
      <h2>Risk Assessment</h2>

      <div className="risk-score-row">
        <div className="risk-score-label">
          Risk score: <strong>{prediction.risk_score.toFixed(1)}</strong> / 100
        </div>
        <div className="risk-score-bar-track">
          <div
            className="risk-score-bar-fill"
            style={{ width: `${prediction.risk_score}%`, backgroundColor: scoreColor }}
          />
        </div>
      </div>

      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-label">Risk Category</div>
          <div className="stat-value" style={{ color: scoreColor }}>
            {prediction.risk_category}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Model Confidence</div>
          <div className="stat-value">
            {prediction.predicted_probability != null
              ? `${(prediction.predicted_probability * 100).toFixed(0)}%`
              : "N/A"}
          </div>
          <div className="stat-sub">
            {prediction.predicted_probability != null
              ? "ML prediction probability"
              : "Rule-based fallback - no ML probability"}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Model Used</div>
          <div className="stat-value">
            {prediction.model_used === "random_forest" ? "Random Forest" : "Rule-based fallback"}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Predicted At</div>
          <div className="stat-value stat-value-small">
            {new Date(prediction.predicted_at).toLocaleString()}
          </div>
        </div>
      </div>

      <p className="hint">
        The risk score (0-100) is a deterministic, rule-based measure and is always available.
        Model confidence is a separate machine-learning probability, only produced when the
        trained Random Forest model made the prediction - the two are never the same thing.
      </p>
    </section>
  );
}

export default RiskAssessmentSection;
