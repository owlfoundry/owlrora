import { defineConfig } from "vitepress";

export default defineConfig({
  title: "OwlRora",
  description: "OwlRora documentation",
  cleanUrls: true,
  sitemap: {
    hostname: "https://owlrora-docs.owlfoundry.org",
  },
  head: [["meta", { name: "theme-color", content: "#111827" }]],
  themeConfig: {
    nav: [
      { text: "Home", link: "/" },
      { text: "GitHub", link: "https://github.com/owlfoundry/owlrora" },
    ],
    socialLinks: [
      { icon: "github", link: "https://github.com/owlfoundry/owlrora" },
    ],
    footer: {
      message: "Released under the BSD 3-Clause License.",
      copyright: "Copyright © 2026 OwlFoundry",
    },
  },
});
