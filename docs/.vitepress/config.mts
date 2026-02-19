import { defineConfig } from 'vitepress'

// https://vitepress.dev/reference/site-config
export default defineConfig({
  base: '/phoenix/',
  title: "Phoenix",
  description: "High-performance, DPI-resistant censorship circumvention tool.",
  head: [
    ['link', { rel: 'icon', href: '/phoenix/logo.png' }]
  ],
  themeConfig: {
    // https://vitepress.dev/reference/default-theme-config
    logo: '/phoenix/logo.png',

    nav: [
      { text: 'Home', link: '/' },
      { text: 'Guide', link: '/guide/getting-started' },
      { text: 'GitHub', link: 'https://github.com/Selin2005/phoenix' }
    ],

    sidebar: [
      {
        text: 'Guide',
        items: [
          { text: 'Getting Started', link: '/guide/getting-started' },
          { text: 'Architecture', link: '/guide/architecture' },
          { text: 'Configuration', link: '/guide/configuration' },
          { text: 'Security & Encryption', link: '/guide/security' }
        ]
      }
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/Selin2005/phoenix' },
      { icon: 'telegram', link: 'https://t.me/FoxFig' } // Added Telegram link as requested
    ],

    footer: {
      message: 'Released under the GPLv2 License.',
      copyright: 'Made with ❤️ at FoxFig. Dedicated to all people of Iran 🇮🇷'
    }
  }
})
