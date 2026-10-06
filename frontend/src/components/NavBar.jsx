import { NavLink, useNavigate } from "react-router-dom";
import { logout } from "../api";

function NavBar() {
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  const linkClass = ({ isActive }) => (isActive ? "nav-link active" : "nav-link");

  return (
    <nav className="nav-bar">
      <div className="nav-brand">HealthSec</div>
      <div className="nav-links">
        <NavLink to="/patients" className={linkClass}>
          Patients
        </NavLink>
        <NavLink to="/dashboard" className={linkClass}>
          Security Dashboard
        </NavLink>
      </div>
      <button type="button" className="secondary nav-logout" onClick={handleLogout}>
        Log Out
      </button>
    </nav>
  );
}

export default NavBar;
