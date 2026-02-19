---
# https://vitepress.dev/reference/default-theme-home-page
layout: home

hero:
  name: "Phoenix"
  text: "Rise Above the Firewalls"
  tagline: High-performance, DPI-resistant censorship circumvention via h2c multiplexing.
  image:
    src: /logo.png
    alt: Phoenix Logo
  actions:
    - theme: brand
      text: Get Started
      link: /guide/getting-started
    - theme: alt
      text: View on GitHub
      link: https://github.com/Selin2005/phoenix

features:
  - title: DPI-Resistant
    details: Uses HTTP/2 Cleartext (h2c) to masquerade as legitimate web traffic, bypassing deep packet inspection.
    icon: 🛡️
  - title: Zero Overhead
    details: Designed for minimal latency and maximum throughput with highly efficient Go implementation.
    icon: ⚡
  - title: CDN Compatible
    details: Works seamlessly behind Cloudflare, Gcore, and other CDNs to mask server IP.
    icon: ☁️

---

<div class="donate-section">
  <h2>Support Development</h2>
  <p>Help keep the fire burning. Donate to support the FoxFig team.</p>
  
  <div class="crypto-wallets">
    <div class="wallet-card">
      <div class="icon">💎</div>
      <h3>Ethereum (ETH)</h3>
      <code>0x0000000000000000000000000000000000000000</code>
    </div>
    <div class="wallet-card">
      <div class="icon">₿</div>
      <h3>Bitcoin (BTC)</h3>
      <code>bc1q00000000000000000000000000000000000000</code>
    </div>
    <div class="wallet-card">
      <div class="icon">💲</div>
      <h3>USDT (TRC20)</h3>
      <code>T000000000000000000000000000000000</code>
    </div>
  </div>
</div>

<style>
.donate-section {
  margin-top: 4rem;
  text-align: center;
  padding: 2rem;
  border-top: 1px solid var(--vp-c-divider);
}

.crypto-wallets {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 1.5rem;
  margin-top: 2rem;
}

.wallet-card {
  padding: 1.5rem;
  border-radius: 12px;
  background-color: var(--vp-c-bg-soft);
  border: 1px solid var(--vp-c-divider);
  transition: transform 0.2s;
}

.wallet-card:hover {
  transform: translateY(-5px);
  border-color: var(--vp-c-brand-1);
}

.wallet-card .icon {
  font-size: 2rem;
  margin-bottom: 0.5rem;
}

.wallet-card code {
  display: block;
  margin-top: 0.5rem;
  font-size: 0.85rem;
  word-break: break-all;
  padding: 0.5rem;
  background-color: var(--vp-c-bg-alt);
  border-radius: 4px;
}
</style>
