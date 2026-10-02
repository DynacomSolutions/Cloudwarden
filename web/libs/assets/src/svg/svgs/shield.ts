import { svg } from "../svg";

// Cloudwarden mark (replaces the upstream shield, see web/NOTICE.md).
const BitwardenShield = svg`
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 42 42" fill="none">
    <path d="M10 33h21a8.5 8.5 0 0 0 1.4-16.9A12 12 0 0 0 9.5 18.6 7.3 7.3 0 0 0 10 33Z" fill="none" stroke-width="3.4" stroke-linejoin="round" class="tw-stroke-fg-nav"/>
    <circle cx="21" cy="24.5" r="3" class="cw-accent-fill" style="fill:#e8414a"/>
    <path d="M21 26.6v4.2" stroke-width="2.8" stroke-linecap="round" style="stroke:#e8414a"/>
  </svg>
`;

export { BitwardenShield };
