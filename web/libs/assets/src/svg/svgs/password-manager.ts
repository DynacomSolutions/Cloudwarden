import { svg } from "../svg";

// Cloudwarden mark and wordmark (replaces the upstream logo, see web/NOTICE.md).
const PasswordManagerLogo = svg`
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 49" fill="none">
    <title>Cloudwarden Password Manager</title>
    <path d="M10 33h21a8.5 8.5 0 0 0 1.4-16.9A12 12 0 0 0 9.5 18.6 7.3 7.3 0 0 0 10 33Z" fill="none" stroke-width="3.4" stroke-linejoin="round" class="tw-stroke-fg-nav"/>
    <circle cx="21" cy="24.5" r="3" class="cw-accent-fill" style="fill:#e8414a"/>
    <path d="M21 26.6v4.2" stroke-width="2.8" stroke-linecap="round" style="stroke:#e8414a"/>
    <text x="52" y="29" font-family="Montserrat, Inter, sans-serif" font-size="22" font-weight="700" textLength="144" lengthAdjust="spacingAndGlyphs" class="tw-fill-fg-nav">Cloudwarden</text>
    <text x="52" y="44" font-family="Montserrat, Inter, sans-serif" font-size="11" font-weight="400" class="tw-fill-fg-nav">Password Manager</text>
  </svg>
`;

export default PasswordManagerLogo;
