import { defineConfig } from "vitepress";

export default defineConfig({
  title: "OwlRora",
  description: "OwlRora — Routing and Observability for Reliable AI",
  cleanUrls: true,
  lastUpdated: true,
  sitemap: {
    hostname: "https://owlrora-docs.owlfoundry.org",
  },
  themeConfig: {
    nav: [
      { text: "Guide", link: "/guide/getting-started" },
      { text: "Deployment", link: "/deployment/" },
      { text: "Status", link: "/reference/implementation-status" },
    ],
    sidebar: [
      {
        text: "Introduction",
        items: [
          { text: "Overview", link: "/overview" },
          { text: "Getting started", link: "/guide/getting-started" },
        ],
      },
      {
        text: "Use OwlRora",
        items: [
          { text: "Management plane", link: "/guide/management" },
          { text: "Gateway plane", link: "/guide/gateway" },
          { text: "CLI and MCP", link: "/guide/cli-and-mcp" },
        ],
      },
      {
        text: "Deploy and operate",
        items: [
          { text: "Deployment", link: "/deployment/" },
          { text: "Configuration", link: "/deployment/configuration" },
          { text: "Production operations", link: "/deployment/operations" },
        ],
      },
      {
        text: "Reference",
        items: [
          {
            text: "Implementation status",
            link: "/reference/implementation-status",
          },
          { text: "Security model", link: "/reference/security" },
        ],
      },
    ],
    search: {
      provider: "local",
    },
    outline: {
      level: [2, 3],
    },
    socialLinks: [
      { icon: "github", link: "https://github.com/owlfoundry/owlrora" },
    ],
    footer: {
      message: "Released under the BSD 3-Clause License.",
      copyright: "Copyright © 2026 OwlFoundry",
    },
  },
});
