// Launcher frame for magpie-simple-share.
// Sandboxed with connect-src 'none': communicates via window.magpie bridge and navigates via location.replace.
(() => {
  const DEFAULT_PORT = 3494;
  const messages = {
    en: {
      title: "Simple Share",
      connecting: "Connecting to the local service…",
      failed: "The local service did not answer.",
      retry: "Try again",
      remote: "This page's service runs only on the computer that runs magpie.",
    },
    "zh-Hans": {
      title: "简单分享",
      connecting: "正在连接本地服务…",
      failed: "本地服务没有响应。",
      retry: "重试",
      remote: "此页面的服务只在运行 magpie 的电脑上可用。",
    },
    "zh-Hant": {
      title: "簡單分享",
      connecting: "正在連線至本機服務…",
      failed: "本機服務沒有回應。",
      retry: "重試",
      remote: "此頁面的服務只在執行 magpie 的電腦上可用。",
    },
  };

  let text = messages["zh-Hans"];

  function languageOf(lang) {
    const parts = String(lang || "zh-Hans").toLowerCase().replaceAll("_", "-").split("-");
    if (parts[0] === "zh") {
      return parts.includes("hant") ||
        (!parts.includes("hans") && parts.some((part) => ["tw", "hk", "mo"].includes(part)))
        ? "zh-Hant"
        : "zh-Hans";
    }
    return parts[0];
  }

  function setLanguage(lang) {
    const key = languageOf(lang);
    text = messages[key] || messages.en;
    if (document.documentElement) document.documentElement.lang = messages[key] ? key : "en";
    document.title = text.title;
    const title = document.getElementById("title");
    if (title) title.textContent = text.title;
    const status = document.getElementById("status");
    if (status) status.textContent = text.connecting;
  }

  function isLocalHost(host) {
    const value = String(host || "").toLowerCase().replace(/^\[|\]$/g, "");
    return !value || value === "localhost" || value.endsWith(".localhost") ||
      value === "::1" || /^127\./.test(value);
  }

  function showFailure(message) {
    const status = document.getElementById("status");
    if (status) status.textContent = message;
    if (!status || document.getElementById("retry")) return;
    const button = document.createElement("button");
    button.id = "retry";
    button.type = "button";
    button.textContent = text.retry;
    button.addEventListener("click", () => location.reload());
    status.after(button);
  }

  function readProviders() {
    const bridge = window.magpie;
    const read = bridge?.read;
    if (typeof read !== "function") {
      return Promise.resolve({ v: 1, ok: false, kind: "bridge-missing" });
    }
    let timer;
    return Promise.race([
      Promise.resolve().then(() => read.call(bridge, "providers:list")),
      new Promise((_, reject) => {
        timer = window.setTimeout(() => reject(new Error("providers:list timed out")), 1500);
      }),
    ])
      .then((value) => ({ v: 1, ok: true, value: value ?? null }))
      .catch((error) => ({
        v: 1,
        ok: false,
        kind: /timed out/i.test(String(error?.message || "")) ? "timeout" : "threw",
        error: String(error?.message || error || "unknown").slice(0, 200),
      }))
      .finally(() => window.clearTimeout?.(timer));
  }

  return (async () => {
    let port = DEFAULT_PORT;
    let theme = "";
    let lang = "";

    try {
      const themeInfo = await window.magpie?.ready;
      if (themeInfo && typeof themeInfo === "object") {
        if (typeof themeInfo.dark === "boolean") theme = themeInfo.dark ? "dark" : "light";
        if (typeof themeInfo.lang === "string" && themeInfo.lang) lang = themeInfo.lang;
      }
    } catch { /* no bridge */ }

    try {
      const options = await window.magpie?.options?.get?.();
      const value = Number(options?.port);
      if (Number.isInteger(value) && value > 0 && value <= 65535) port = value;
    } catch { /* default port */ }

    if (!lang) {
      try { lang = new URLSearchParams(location.search).get("lang") || ""; } catch { /* ignore */ }
    }
    setLanguage(lang);

    let service = "";
    try {
      const offered = window.magpie?.service;
      if (typeof offered === "string" && /^https?:\/\//.test(offered)) service = offered;
    } catch { /* older magpie */ }

    if (!service && !isLocalHost(location.hostname)) {
      showFailure(text.remote);
      return;
    }

    const target = new URL(service || `http://127.0.0.1:${port}/`, location.href);
    if (theme) target.searchParams.set("theme", theme);
    if (lang) target.searchParams.set("lang", lang);

    const providerRead = await readProviders();
    target.hash = `providers=${encodeURIComponent(JSON.stringify(providerRead))}`;

    let attempts = 0;
    const MAX_ATTEMPTS = 120;
    const RETRY_MS = 1500;
    let interval = null;
    const stop = () => {
      if (interval !== null) window.clearInterval?.(interval);
      interval = null;
    };
    const navigate = () => {
      attempts += 1;
      const url = new URL(target.href);
      if (attempts > 1) url.searchParams.set("retry", String(attempts));
      location.replace(url.href);
      if (attempts >= MAX_ATTEMPTS) {
        stop();
        showFailure(text.failed);
      }
    };
    navigate();
    interval = window.setInterval(navigate, RETRY_MS);
    window.addEventListener?.("pagehide", stop, { once: true });
  })().catch((error) => {
    showFailure(`${text.failed} ${String(error?.message || error)}`);
  });
})();
