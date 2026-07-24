import { useState } from "react";
import { Link, useLocation } from "react-router-dom";
import useTheme from "../hooks/useTheme";

const LINKS = [
  { to: "/", label: "Home" },
  { to: "/analyze", label: "Analyze" },
  { to: "/about", label: "About" },
];

export default function Navbar() {
  const [menuOpen, setMenuOpen] = useState(false);
  const location = useLocation();
  const { theme, toggle } = useTheme();

  return (
    <nav className="navbar">
      <div className="navbar-inner">
        <Link to="/" className="navbar-brand">
          MINOS
        </Link>
        <button
          className="hamburger"
          onClick={() => setMenuOpen(!menuOpen)}
          aria-label="Toggle navigation"
        >
          {menuOpen ? "✕" : "☰"}
        </button>
        <div className={`nav-links${menuOpen ? " open" : ""}`}>
          {LINKS.map((link) => (
            <Link
              key={link.to}
              to={link.to}
              className={`nav-link${location.pathname === link.to ? " active" : ""}`}
              onClick={() => setMenuOpen(false)}
            >
              {link.label}
            </Link>
          ))}
          <button
            className="nav-link theme-toggle"
            onClick={toggle}
            aria-label="Toggle dark mode"
            title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
          >
            {theme === "dark" ? "☀️" : "🌙"}
          </button>
        </div>
      </div>
    </nav>
  );
}
