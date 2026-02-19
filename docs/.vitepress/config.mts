import { defineConfig } from 'vitepress'

// https://vitepress.dev/reference/site-config
export default defineConfig({
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
      html[lang="fa-IR"] { --vp-font-family-base: "Vazirmatn", sans-serif; }
    `]
  ],

  themeConfig: {
    logo: '/phoenix/logo.png',
    socialLinks: [
      { icon: 'github', link: 'https://github.com/Selin2005/phoenix' },
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
        footer: {
          message: 'Released under the GPLv2 License.',
          copyright: 'Made with ❤️ at FoxFig. Dedicated to all people of Iran 🕊️'
        }
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
          { text: 'گیت‌هاب', link: 'https://github.com/Selin2005/phoenix' }
        ],
        sidebar: [
          {
            text: 'راهنما',
            items: [
              { text: 'شروع کنید', link: '/fa/guide/getting-started' },
              { text: 'معماری و پروتکل', link: '/fa/guide/architecture' },
              { text: 'پیکربندی (Config)', link: '/fa/guide/configuration' },
              { text: 'امنیت و رمزنگاری', link: '/fa/guide/security' }
            ]
          }
        ],
        footer: {
          message: 'تحت مجوز GPLv2 منتشر شده است.',
          copyright: 'ساخته شده با ❤️ در FoxFig. تقدیم به تمام مردم ایران 🇮🇷'
        },
        docFooter: { prev: 'صفحه قبل', next: 'صفحه بعد' },
        outline: { label: 'در این صفحه' },
        darkModeSwitchLabel: 'حالت تاریک',
        sidebarMenuLabel: 'منو',
        returnToTopLabel: 'بازگشت به بالا',
        langMenuLabel: 'تغییر زبان'
      }
    }
  }
})
