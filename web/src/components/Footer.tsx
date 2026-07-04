import { Link } from "react-router-dom";

export default function Footer() {
  return (
    <footer>
      <p>
        MINOS &mdash; Auto-Triage SOC Bot{" "}
        | <Link to="/about">Docs</Link>{" "}
        | <a href="https://github.com/KiZINnO/MINOS" target="_blank" rel="noreferrer">GitHub</a>
      </p>
    </footer>
  );
}
