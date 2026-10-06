import { useEffect, useState } from "react";
import {
  getApplications,
  getDashboardStats,
  getDeploymentHistory,
  getScanDeploymentDecision,
  getScanDetail,
  getScanExplanation,
  getScanFindings,
  getScanHistory,
  getScanPrediction,
  getScanRecommendations,
} from "../api";
import LoadingSpinner from "../components/LoadingSpinner";
import ErrorMessage from "../components/ErrorMessage";
import NavBar from "../components/NavBar";
import ApplicationSelector from "../components/dashboard/ApplicationSelector";
import OverviewSection from "../components/dashboard/OverviewSection";
import ScanHistoryTable from "../components/dashboard/ScanHistoryTable";
import SecurityReportsSection from "../components/dashboard/SecurityReportsSection";
import RiskAssessmentSection from "../components/dashboard/RiskAssessmentSection";
import ExplainableAISection from "../components/dashboard/ExplainableAISection";
import RecommendationsSection from "../components/dashboard/RecommendationsSection";
import DeploymentDecisionCard from "../components/dashboard/DeploymentDecisionCard";
import DeploymentHistoryTable from "../components/dashboard/DeploymentHistoryTable";

const RISK_TREND_LIMIT = 10;

function Dashboard() {
  // Applications
  const [applications, setApplications] = useState([]);
  const [applicationsLoading, setApplicationsLoading] = useState(true);
  const [applicationsError, setApplicationsError] = useState(null);
  const [selectedApplication, setSelectedApplication] = useState(null);

  // Overview stats + scan history for the selected application
  const [stats, setStats] = useState(null);
  const [statsLoading, setStatsLoading] = useState(false);
  const [statsError, setStatsError] = useState(null);

  const [scans, setScans] = useState([]);
  const [scansLoading, setScansLoading] = useState(false);
  const [scansError, setScansError] = useState(null);
  const [riskTrend, setRiskTrend] = useState([]);

  // Selected scan detail
  const [selectedScanUuid, setSelectedScanUuid] = useState(null);
  const [scanFeatures, setScanFeatures] = useState(null);
  const [scanFindings, setScanFindings] = useState([]);
  const [scanPrediction, setScanPrediction] = useState(null);
  const [scanExplanation, setScanExplanation] = useState(null);
  const [scanRecommendations, setScanRecommendations] = useState(null);
  const [scanDeploymentDecision, setScanDeploymentDecision] = useState(null);
  const [scanDetailLoading, setScanDetailLoading] = useState(false);
  const [scanDetailError, setScanDetailError] = useState(null);

  // Global deployment history
  const [deploymentHistory, setDeploymentHistory] = useState([]);
  const [deploymentHistoryLoading, setDeploymentHistoryLoading] = useState(true);
  const [deploymentHistoryError, setDeploymentHistoryError] = useState(null);

  // --- Load applications on mount ---
  const loadApplications = async () => {
    setApplicationsLoading(true);
    setApplicationsError(null);
    try {
      const data = await getApplications();
      setApplications(data);
      if (data.length > 0) {
        setSelectedApplication((current) => current || data[0].name);
      }
    } catch (err) {
      setApplicationsError("Could not load applications.");
    } finally {
      setApplicationsLoading(false);
    }
  };

  useEffect(() => {
    loadApplications();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // --- Load stats + scan history whenever the selected application changes ---
  const loadStatsAndScans = async (applicationName) => {
    setStatsLoading(true);
    setStatsError(null);
    setScansLoading(true);
    setScansError(null);
    setSelectedScanUuid(null);

    try {
      const statsData = await getDashboardStats(applicationName);
      setStats(statsData);
    } catch (err) {
      setStatsError("Could not load overview stats.");
    } finally {
      setStatsLoading(false);
    }

    try {
      const scansData = await getScanHistory(applicationName);
      setScans(scansData);
      if (scansData.length > 0) {
        setSelectedScanUuid(scansData[0].scan_uuid);
      }
    } catch (err) {
      setScansError("Could not load scan history.");
    } finally {
      setScansLoading(false);
    }
  };

  useEffect(() => {
    if (selectedApplication) {
      loadStatsAndScans(selectedApplication);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedApplication]);

  // --- Build the risk-score trend chart from real prediction data ---
  useEffect(() => {
    const buildTrend = async () => {
      const recentScans = [...scans].slice(0, RISK_TREND_LIMIT).reverse(); // chronological order
      const results = await Promise.allSettled(recentScans.map((s) => getScanPrediction(s.scan_uuid)));

      const trend = results
        .map((result, index) => {
          if (result.status !== "fulfilled") return null;
          const scan = recentScans[index];
          return {
            label: scan.commit_sha ? scan.commit_sha.slice(0, 7) : scan.scan_uuid.slice(0, 8),
            risk_score: result.value.risk_score,
          };
        })
        .filter(Boolean);

      setRiskTrend(trend);
    };

    if (scans.length > 0) {
      buildTrend();
    } else {
      setRiskTrend([]);
    }
  }, [scans]);

  // --- Load full detail for the selected scan ---
  const loadScanDetail = async (scanUuid) => {
    setScanDetailLoading(true);
    setScanDetailError(null);
    try {
      const [detail, findings, prediction, explanation, recommendations, decision] = await Promise.all([
        getScanDetail(scanUuid),
        getScanFindings(scanUuid),
        getScanPrediction(scanUuid),
        getScanExplanation(scanUuid),
        getScanRecommendations(scanUuid),
        getScanDeploymentDecision(scanUuid),
      ]);
      setScanFeatures(detail.features);
      setScanFindings(findings);
      setScanPrediction(prediction);
      setScanExplanation(explanation);
      setScanRecommendations(recommendations);
      setScanDeploymentDecision(decision);
    } catch (err) {
      setScanDetailError("Could not load details for this scan.");
    } finally {
      setScanDetailLoading(false);
    }
  };

  useEffect(() => {
    if (selectedScanUuid) {
      loadScanDetail(selectedScanUuid);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedScanUuid]);

  // --- Load global deployment history once ---
  const loadDeploymentHistory = async () => {
    setDeploymentHistoryLoading(true);
    setDeploymentHistoryError(null);
    try {
      const data = await getDeploymentHistory();
      setDeploymentHistory(data);
    } catch (err) {
      setDeploymentHistoryError("Could not load deployment history.");
    } finally {
      setDeploymentHistoryLoading(false);
    }
  };

  useEffect(() => {
    loadDeploymentHistory();
  }, []);

  return (
    <div>
      <NavBar />
      <div className="page dashboard-page">
      <header className="page-header">
        <div>
          <h1>Security Dashboard</h1>
          <p className="hint">DevSecOps risk assessment results, pulled live from the API.</p>
        </div>
      </header>

      {applicationsLoading ? (
        <LoadingSpinner label="Loading applications..." />
      ) : applicationsError ? (
        <ErrorMessage message={applicationsError} onRetry={loadApplications} />
      ) : (
        <ApplicationSelector
          applications={applications}
          selectedApplication={selectedApplication}
          onSelect={setSelectedApplication}
        />
      )}

      {selectedApplication && (
        <>
          {statsLoading ? (
            <LoadingSpinner label="Loading overview..." />
          ) : statsError ? (
            <ErrorMessage message={statsError} onRetry={() => loadStatsAndScans(selectedApplication)} />
          ) : (
            <OverviewSection stats={stats} />
          )}

          <section className="dashboard-section">
            <h2>Scan History</h2>
            {scansLoading ? (
              <LoadingSpinner label="Loading scan history..." />
            ) : scansError ? (
              <ErrorMessage message={scansError} onRetry={() => loadStatsAndScans(selectedApplication)} />
            ) : (
              <ScanHistoryTable
                scans={scans}
                riskTrend={riskTrend}
                selectedScanUuid={selectedScanUuid}
                onSelectScan={setSelectedScanUuid}
              />
            )}
          </section>

          {selectedScanUuid && (
            <>
              {scanDetailLoading ? (
                <LoadingSpinner label="Loading scan details..." />
              ) : scanDetailError ? (
                <ErrorMessage
                  message={scanDetailError}
                  onRetry={() => loadScanDetail(selectedScanUuid)}
                />
              ) : (
                <>
                  <SecurityReportsSection features={scanFeatures} findings={scanFindings} />
                  <RiskAssessmentSection prediction={scanPrediction} />
                  <ExplainableAISection explanation={scanExplanation} />
                  <RecommendationsSection recommendations={scanRecommendations} />
                  <DeploymentDecisionCard decision={scanDeploymentDecision} />
                </>
              )}
            </>
          )}
        </>
      )}

      {deploymentHistoryLoading ? (
        <LoadingSpinner label="Loading deployment history..." />
      ) : deploymentHistoryError ? (
        <ErrorMessage message={deploymentHistoryError} onRetry={loadDeploymentHistory} />
      ) : (
        <DeploymentHistoryTable history={deploymentHistory} />
      )}
      </div>
    </div>
  );
}

export default Dashboard;
