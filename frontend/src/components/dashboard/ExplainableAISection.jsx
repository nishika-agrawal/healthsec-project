import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

const METHOD_LABELS = {
  shap_tree_explainer: "SHAP (trained Random Forest)",
  rule_based_breakdown: "Rule-based breakdown (fallback)",
};

function ExplainableAISection({ explanation }) {
  if (!explanation) return null;

  const chartData = explanation.contributions.map((c) => ({
    feature: c.feature.replace(/_/g, " "),
    contribution: c.contribution,
    direction: c.direction,
  }));

  return (
    <section className="dashboard-section">
      <h2>Explainable AI</h2>
      <p className="hint">Method: {METHOD_LABELS[explanation.method] || explanation.method}</p>

      {chartData.length > 0 && (
        <div className="chart-container">
          <ResponsiveContainer width="100%" height={Math.max(180, chartData.length * 40)}>
            <BarChart data={chartData} layout="vertical" margin={{ left: 40 }}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis type="number" tick={{ fontSize: 12 }} />
              <YAxis type="category" dataKey="feature" width={160} tick={{ fontSize: 12 }} />
              <Tooltip />
              <Bar dataKey="contribution" name="Contribution" radius={[0, 4, 4, 0]}>
                {chartData.map((entry, index) => (
                  <Cell
                    key={index}
                    fill={
                      entry.direction === "increases"
                        ? "#b91c1c"
                        : entry.direction === "decreases"
                        ? "#16a34a"
                        : "#6b7280"
                    }
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      <p className="explanation-summary">{explanation.summary}</p>
    </section>
  );
}

export default ExplainableAISection;
