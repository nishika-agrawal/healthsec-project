import axios from "axios";

// The backend URL is read from an environment variable so it can differ
// between local development, CI, and production without changing code.
const API_BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

const api = axios.create({
  baseURL: API_BASE_URL,
});

// Attach the saved JWT token (if any) to every outgoing request.
api.interceptors.request.use((config) => {
  const token = localStorage.getItem("access_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const login = async (username, password) => {
  const formData = new URLSearchParams();
  formData.append("username", username);
  formData.append("password", password);
  const response = await api.post("/auth/login", formData, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
  });
  return response.data;
};

export const logout = () => {
  localStorage.removeItem("access_token");
};

export const isLoggedIn = () => Boolean(localStorage.getItem("access_token"));

export const getPatients = () => api.get("/patients").then((res) => res.data);

export const getPatient = (id) => api.get(`/patients/${id}`).then((res) => res.data);

export const createPatient = (data) => api.post("/patients", data).then((res) => res.data);

export const updatePatient = (id, data) =>
  api.put(`/patients/${id}`, data).then((res) => res.data);

export const deletePatient = (id) => api.delete(`/patients/${id}`);

// ---------------------------------------------------------------------
// Security dashboard (Phase 9)
// ---------------------------------------------------------------------

export const getApplications = () => api.get("/applications").then((res) => res.data);

export const getDashboardStats = (applicationName) =>
  api
    .get("/dashboard/stats", { params: { application_name: applicationName } })
    .then((res) => res.data);

export const getScanHistory = (applicationName, limit = 25) =>
  api
    .get("/scans", { params: { application_name: applicationName, limit } })
    .then((res) => res.data);

export const getScanDetail = (scanUuid) => api.get(`/scans/${scanUuid}`).then((res) => res.data);

export const getScanFindings = (scanUuid) =>
  api.get(`/scans/${scanUuid}/findings`).then((res) => res.data);

export const getScanPrediction = (scanUuid) =>
  api.get(`/scans/${scanUuid}/prediction`).then((res) => res.data);

export const getScanExplanation = (scanUuid) =>
  api.get(`/scans/${scanUuid}/explanation`).then((res) => res.data);

export const getScanRecommendations = (scanUuid) =>
  api.get(`/scans/${scanUuid}/recommendations`).then((res) => res.data);

export const getScanDeploymentDecision = (scanUuid) =>
  api.get(`/scans/${scanUuid}/deployment-decision`).then((res) => res.data);

export const getDeploymentHistory = (limit = 25) =>
  api.get("/deployments", { params: { limit } }).then((res) => res.data);

export default api;
