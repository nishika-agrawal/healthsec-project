import { Navigate } from "react-router-dom";
import { isLoggedIn } from "../api";

/**
 * Wrap any route element with this component to require a logged-in user.
 * Example: <ProtectedRoute><Patients /></ProtectedRoute>
 */
function ProtectedRoute({ children }) {
  if (!isLoggedIn()) {
    return <Navigate to="/login" replace />;
  }
  return children;
}

export default ProtectedRoute;
