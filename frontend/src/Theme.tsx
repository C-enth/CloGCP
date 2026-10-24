import { useState } from "react";

/** Dark (default) / Light / System. public/theme-init.js applies the saved choice before first
 * paint (Dark when nothing is saved) and follows the OS while "System" is selected; this
 * control only changes the choice. */
export type ThemeChoice = "light" | "dark" | "system";
export const THEME_KEY = "closec-theme";

function current(): ThemeChoice {
  const value = document.documentElement.getAttribute("data-theme-preference");
  return value === "light" || value === "system" ? value : "dark";
}

export function applyTheme(choice: ThemeChoice) {
  const dark =
    choice === "dark" ||
    (choice === "system" &&
      !!window.matchMedia?.("(prefers-color-scheme: dark)").matches);
  const root = document.documentElement;
  root.setAttribute("data-theme", dark ? "dark" : "light");
  root.setAttribute("data-theme-preference", choice);
  try {
    window.localStorage.setItem(THEME_KEY, choice);
  } catch {
    // Storage may be unavailable; the choice still applies to this page.
  }
}

export function ThemeToggle() {
  const [choice, setChoice] = useState<ThemeChoice>(current);
  return (
    <label className="theme-toggle">
      Theme
      <select
        aria-label="Colour theme"
        value={choice}
        onChange={(e) => {
          const next = e.target.value as ThemeChoice;
          applyTheme(next);
          setChoice(next);
        }}
      >
        <option value="dark">Dark (default)</option>
        <option value="light">Light</option>
        <option value="system">System</option>
      </select>
    </label>
  );
}
