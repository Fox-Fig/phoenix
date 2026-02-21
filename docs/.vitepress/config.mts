import { defineConfig } from 'vitepress'
import { withMermaid } from 'vitepress-plugin-mermaid'

// https://vitepress.dev/reference/site-config
export default withMermaid(defineConfig({
  base: '/phoenix/',
  title: "Phoenix",
  description: "High-performance, DPI-resistant censorship circumvention tool.",

  head: [
    ['link', { rel: 'icon', href: '/phoenix/logo.png' }],
    ['link', { rel: 'preconnect', href: 'https://fonts.googleapis.com' }],
    ['link', { rel: 'preconnect', href: 'https://fonts.gstatic.com', crossorigin: '' }],
    ['link', { href: 'https://fonts.googleapis.com/css2?family=Vazirmatn:wght@100..900&display=swap', rel: 'stylesheet' }],
    ['style', {}, `
      :root { --vp-font-family-base: "Inter", sans-serif; }
      html[lang="fa-IR"] { 
        --vp-font-family-base: "Vazirmatn", sans-serif; 
        direction: rtl;
        text-align: right;
      }
      /* RTL Support for Hero Section */
      html[lang="fa-IR"] .VPImage { margin-left: 0; margin-right: auto; }
      html[lang="fa-IR"] .VPHero .text { text-align: right; }
      html[lang="fa-IR"] .VPHero .tagline { text-align: right; }
      html[lang="fa-IR"] .VPHero .name { text-align: right; }
      
      /* RTL Support for Features */
      html[lang="fa-IR"] .VPFeature { text-align: right; }
      
      /* RTL Support for Sidebar */
      html[lang="fa-IR"] .VPSidebar { text-align: right; border-right: none; border-left: 1px solid var(--vp-c-divider); }
      html[lang="fa-IR"] .VPSidebarItem .text { padding-top: 4px; padding-bottom: 4px; }
      
      /* RTL Support for Navbar */
      html[lang="fa-IR"] .VPNavBarTitle { margin-right: 0; margin-left: 12px; }
      
      /* Center Mermaid Diagrams */
      .mermaid { display: flex !important; justify-content: center !important; }
    `]
  ],

  themeConfig: {
    logo: '/phoenix/logo.png',
    socialLinks: [
      { icon: 'github', link: 'https://github.com/Fox-Fig/phoenix' },
      {
        icon: {
          svg: '<svg role="img" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><title>Telegram</title><path d="M11.944 0A12 12 0 0 0 0 12a12 12 0 0 0 12 12 12 12 0 0 0 12-12A12 12 0 0 0 11.944 0zm4.925 8.531l-1.97 9.28c-.145.658-.537.818-1.084.508l-3-2.21-1.446 1.394c-.14.18-.357.223-.535.223l.192-3.05 5.547-5.029c.24-.214-.054-.334-.373-.121l-6.869 4.326-2.96-.924c-.64-.203-.658-.64.135-.954l11.566-4.458c.538-.196 1.006.128.832.941z"/></svg>'
        },
        link: 'https://t.me/FoxFig'
      }
    ],
  },

  locales: {
    root: {
      label: 'English',
      lang: 'en',
      themeConfig: {
        nav: [
          { text: 'Home', link: '/' },
          { text: 'Guide', link: '/guide/getting-started' },
          { text: 'GitHub', link: 'https://github.com/Fox-Fig/phoenix' }
        ],
        sidebar: [
          {
            text: 'Guide',
            items: [
              { text: 'Getting Started', link: '/guide/getting-started' },
              { text: 'Installation', link: '/guide/installation' },
              { text: 'Advanced Configuration', link: '/guide/configuration' },
              { text: 'Manage with Systemd', link: '/guide/systemd' },
              { text: 'Troubleshooting & Logs', link: '/guide/troubleshooting' },
              { text: 'Architecture & Security', link: '/guide/architecture' }
            ]
          }
        ],
        footer: {
          message: 'Released under the GPLv2 License.',
          copyright: 'Made with ❤️ at FoxFig. Dedicated to all people of Iran 🇮🇷'
        },
        outline: { level: [2, 3] }
      }
    },
    fa: {
      label: 'فارسی',
      lang: 'fa-IR',
      dir: 'rtl',
      title: 'ققنوس (Phoenix)',
      description: 'ابزار قدرتمند عبور از فیلترینگ',
      themeConfig: {
        nav: [
          { text: 'خانه', link: '/fa/' },
          { text: 'راهنما', link: '/fa/guide/getting-started' },
          { text: 'گیت‌هاب', link: 'https://github.com/Fox-Fig/phoenix' }
        ],
        sidebar: [
          {
            text: 'راهنما',
            items: [
              { text: 'معرفی و کلیات', link: '/fa/guide/getting-started' },
              { text: 'نصب و راه‌اندازی', link: '/fa/guide/installation' },
              { text: 'پیکربندی پیشرفته', link: '/fa/guide/configuration' },
              { text: 'مدیریت با Systemd', link: '/fa/guide/systemd' },
              { text: 'رفع اشکال و خطاها', link: '/fa/guide/troubleshooting' },
              { text: 'معماری و امنیت', link: '/fa/guide/architecture' }
            ]
          }
        ],
        footer: {
          message: 'تحت مجوز GPLv2 منتشر شده است.',
          copyright: 'ساخته شده با ❤️ در FoxFig. تقدیم به تمام مردم ایران 🇮🇷'
        },
        docFooter: { prev: 'صفحه قبل', next: 'صفحه بعد' },
        outline: { label: 'در این صفحه', level: [2, 3] },
        darkModeSwitchLabel: 'حالت تاریک',
        sidebarMenuLabel: 'منو',
        returnToTopLabel: 'بازگشت به بالا',
        langMenuLabel: 'تغییر زبان'
      }
    }
  }
}))
