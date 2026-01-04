// 统一的页面渲染与基础样式：Admin / Dashboard 共享，避免两套 UI 长期漂移。

// 注意：这里的 CSS tokens 与组件样式原始来源于 src/admin.ts，迁移时保持不改语义，确保两端风格一致。
export function baseStyles() {
  // Inspired by shadcn/ui tokens (HSL via CSS variables). Intentionally avoids HEX colors.
  return `
    :root{
      --background: 48 33% 97%;
      --foreground: 222 47% 11%;
      --card: 0 0% 100%;
      --card-foreground: 222 47% 11%;
      --muted: 210 40% 96%;
      --muted-foreground: 215 16% 47%;
      --popover: 0 0% 100%;
      --popover-foreground: 222 47% 11%;
      --border: 214 32% 91%;
      --input: 214 32% 91%;
      --primary: 142 71% 30%;
      --primary-foreground: 0 0% 100%;
      --ring: 142 71% 30%;
      --radius: 0.9rem;
      --shadow: 0 1px 2px hsl(222 47% 11% / 0.05), 0 12px 24px hsl(222 47% 11% / 0.08);
      --shadow-sm: 0 1px 2px hsl(222 47% 11% / 0.06);
    }

    *{box-sizing:border-box}
    html,body{height:100%}
    body{
      margin:0;
      color:hsl(var(--foreground));
      background:hsl(var(--background));
      font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,"Apple Color Emoji","Segoe UI Emoji";
      line-height:1.5;
    }

    a{color:inherit;text-decoration:none}
    a:hover{text-decoration:underline}

    .container{width:100%;max-width:64rem;margin:0 auto;padding:0 16px}
    @media (min-width: 640px){.container{padding:0 24px}}
    @media (min-width: 1024px){.container{padding:0 32px}}

    .shell{min-height:100%;background:hsl(var(--muted) / 0.35)}

    .topbar{
      position:sticky;top:0;z-index:20;
      background:hsl(var(--background) / 0.85);
      backdrop-filter:saturate(1.2) blur(10px);
      border-bottom:1px solid hsl(var(--border));
    }
    .topbar-inner{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:14px 0}

    .brand{display:flex;align-items:center;gap:10px;min-width:220px}
    .logo{
      display:inline-flex;align-items:center;justify-content:center;
      width:28px;height:28px;border-radius:8px;
      background:hsl(var(--foreground));color:hsl(var(--background));
      font-weight:700;font-size:12px;letter-spacing:0.02em;
      box-shadow:var(--shadow-sm);
      flex:0 0 auto;
    }
    .brand-title{font-weight:650}
    .workspace{
      display:inline-flex;align-items:center;gap:8px;
      border:1px solid hsl(var(--border));
      background:hsl(var(--popover));
      padding:6px 10px;border-radius:999px;
      color:hsl(var(--muted-foreground));
      font-size:12px;
    }

    .nav{display:none;align-items:center;gap:18px}
    @media (min-width: 720px){.nav{display:flex}}
    .nav a{font-size:13px;color:hsl(var(--muted-foreground));padding:8px 2px}
    .nav a[data-active="true"]{color:hsl(var(--foreground));font-weight:600;border-bottom:2px solid hsl(var(--primary));text-decoration:none}
    .nav a[aria-disabled="true"]{opacity:0.6;pointer-events:none}

    .actions{display:flex;align-items:center;gap:10px}
    .link{font-size:13px;color:hsl(var(--muted-foreground))}

    .btn{
      display:inline-flex;align-items:center;justify-content:center;gap:8px;
      height:34px;padding:0 12px;border-radius:10px;
      border:1px solid hsl(var(--border));
      background:hsl(var(--popover));
      color:hsl(var(--foreground));
      font-weight:600;font-size:13px;
      cursor:pointer;
    }
    .btn[disabled]{opacity:0.55;cursor:not-allowed}
    .btn:focus{outline:none;box-shadow:0 0 0 3px hsl(var(--ring) / 0.25)}
    .btn-primary{
      border-color:hsl(var(--primary));
      background:hsl(var(--primary));
      color:hsl(var(--primary-foreground));
    }
    /* Dashboard 需要的危险操作按钮（Admin 不使用，但放在共享样式里便于统一风格） */
    .btn-danger{
      border-color:hsl(0 84% 60% / 0.35);
      background:hsl(0 84% 60% / 0.06);
      color:hsl(0 72% 35%);
    }

    main{padding:28px 0 48px}
    .stack{display:flex;flex-direction:column;gap:22px}

    .tabs{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
    .tab{
      height:34px;padding:0 12px;border-radius:999px;border:1px solid hsl(var(--border));
      background:hsl(var(--popover));color:hsl(var(--muted-foreground));
      font-weight:600;font-size:13px;cursor:pointer;
    }
    .tab[data-active="true"]{border-color:hsl(var(--primary));color:hsl(var(--foreground));box-shadow:0 0 0 3px hsl(var(--ring) / 0.12)}

    .grid{display:grid;gap:14px}
    .grid-4{grid-template-columns:repeat(1,minmax(0,1fr))}
    @media (min-width: 720px){.grid-4{grid-template-columns:repeat(4,minmax(0,1fr))}}

    /* Dashboard「API」页：长命令/JSON 在 grid 下容易撑破布局，这里强制可收缩并启用视觉换行 */
    .api-grid{display:grid;gap:12px;grid-template-columns:minmax(0,1fr)}
    .api-grid > *{min-width:0}
    .api-grid pre{max-width:100%;white-space:pre-wrap;overflow-wrap:anywhere}

    .card{
      background:hsl(var(--card));
      border:1px solid hsl(var(--border));
      border-radius:calc(var(--radius) + 6px);
      box-shadow:var(--shadow-sm);
    }
    .card-pad{padding:16px}
    .kicker{font-size:11px;letter-spacing:0.06em;text-transform:uppercase;color:hsl(var(--muted-foreground))}
    .value{margin-top:6px;font-size:22px;font-weight:700}
    .sub{margin-top:2px;font-size:12px;color:hsl(var(--muted-foreground))}

    .section-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}
    .section-title{margin:0;font-size:15px;font-weight:700}
    .section-desc{margin:4px 0 0;font-size:13px;color:hsl(var(--muted-foreground))}

    .table{width:100%;border-collapse:collapse}
    .table th,.table td{padding:10px 12px;border-top:1px solid hsl(var(--border));font-size:13px;text-align:left;vertical-align:middle}
    .table th{color:hsl(var(--muted-foreground));font-size:11px;letter-spacing:0.06em;text-transform:uppercase}
    .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace}

    /* Admin 表格：时间两行展示（UTC），更易扫读 */
    .when{display:flex;flex-direction:column;gap:2px;line-height:1.2}
    .when-primary{font-weight:650}
    .when-sub{font-size:12px;color:hsl(var(--muted-foreground))}

    /* 表格行操作：更紧凑、更对齐 */
    .row-actions{display:flex;align-items:center;justify-content:flex-start;gap:10px}
    .btn-sm{height:30px;padding:0 10px;border-radius:10px;font-size:12px}

    /* 更丰富的状态样式 */
    .badge-muted{background:hsl(var(--muted) / 0.4);color:hsl(var(--muted-foreground))}
    .badge-danger{border-color:hsl(0 84% 60% / 0.35);background:hsl(0 84% 60% / 0.10);color:hsl(0 72% 35%)}
    .dot{width:7px;height:7px;border-radius:999px;background:currentColor;opacity:0.9}
    .dot-ok{color:hsl(var(--primary))}
    .dot-warn{color:hsl(32 90% 30%)}
    .dot-danger{color:hsl(0 72% 35%)}
    .badge{
      display:inline-flex;align-items:center;gap:6px;
      height:22px;padding:0 8px;border-radius:999px;
      font-size:12px;font-weight:650;
      border:1px solid hsl(var(--border));
      background:hsl(var(--muted) / 0.55);
      color:hsl(var(--foreground));
    }
    .badge-ok{border-color:hsl(var(--primary) / 0.45);background:hsl(var(--primary) / 0.08);color:hsl(var(--primary))}
    .badge-warn{border-color:hsl(48 96% 55% / 0.55);background:hsl(48 96% 55% / 0.16);color:hsl(32 90% 30%)}

    .field{display:flex;align-items:center;gap:10px;padding:10px 12px;border:1px solid hsl(var(--border));border-radius:12px;background:hsl(var(--popover))}
    .field input{
      border:0;outline:none;background:transparent;
      width:100%;font-size:13px;color:hsl(var(--foreground));
    }
    .icon-btn{
      flex:0 0 auto;
      height:28px;width:28px;border-radius:10px;
      border:1px solid hsl(var(--border));background:hsl(var(--muted) / 0.45);
      cursor:pointer;
    }
    .icon-btn[disabled]{opacity:0.55;cursor:not-allowed}
    .icon-btn[data-copied="true"]{border-color:hsl(var(--primary));box-shadow:0 0 0 3px hsl(var(--ring) / 0.12)}

    .radio-group{display:grid;gap:10px;margin-top:12px}
    .radio{
      display:flex;gap:10px;align-items:flex-start;
      padding:12px 12px;border-radius:16px;
      border:1px solid hsl(var(--border));
      background:hsl(var(--popover));
      cursor:default;
    }
    .radio[data-selected="true"]{border-color:hsl(var(--primary));box-shadow:0 0 0 3px hsl(var(--ring) / 0.12)}
    .radio input{margin-top:3px}
    .radio .title{font-weight:650;font-size:13px}
    .radio .desc{margin-top:3px;color:hsl(var(--muted-foreground));font-size:13px}

    pre{
      margin:0;
      background:hsl(222 47% 11%);
      color:hsl(210 40% 96%);
      border-radius:calc(var(--radius) + 4px);
      border:1px solid hsl(214 32% 20%);
      padding:12px 14px;
      overflow:auto;
      box-shadow:var(--shadow-sm);
    }

    .callout{
      display:flex;align-items:flex-start;justify-content:space-between;gap:12px;
      padding:14px 16px;border-radius:calc(var(--radius) + 4px);
      border:1px solid hsl(48 96% 55% / 0.55);
      background:hsl(48 96% 55% / 0.18);
    }
    .callout strong{font-size:13px}
    .callout p{margin:4px 0 0;font-size:13px;color:hsl(var(--muted-foreground))}

    .auth{
      max-width:480px;margin:0 auto;padding:44px 16px;
    }
    .auth h1{margin:0 0 10px;font-size:22px}
    .auth .hint{margin:0 0 18px;color:hsl(var(--muted-foreground));font-size:13px}
    .form{display:flex;flex-direction:column;gap:12px}
    label{display:block;font-size:12px;color:hsl(var(--muted-foreground));font-weight:650}
    .input{
      width:100%;
      height:40px;
      padding:0 12px;
      border-radius:12px;
      border:1px solid hsl(var(--input));
      background:hsl(var(--popover));
      color:hsl(var(--foreground));
      font-size:14px;
      outline:none;
    }
    .input:focus{box-shadow:0 0 0 3px hsl(var(--ring) / 0.18);border-color:hsl(var(--ring) / 0.65)}
    .muted{color:hsl(var(--muted-foreground))}
  `;
}

export function layoutHtml(opts: { title: string; body: string; scripts?: string }) {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>${escapeHtml(opts.title)}</title>
  <style>${baseStyles()}</style>
</head>
<body>
${opts.body}
${opts.scripts ? `<script>${opts.scripts}</script>` : ""}
</body>
</html>`;
}

export function iconCopySvg() {
  return `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" aria-hidden="true">
  <path d="M8 8h10v12H8V8Z" stroke="currentColor" stroke-width="1.8" />
  <path d="M6 16H5a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" />
</svg>`;
}

export function escapeAttr(input: unknown) {
  // Keep it safe for inclusion inside a double-quoted attribute.
  return escapeHtml(input).replaceAll("\n", "&#10;").replaceAll("\r", "&#13;");
}

export function escapeHtml(input: unknown) {
  const s = input === null || input === undefined ? "" : String(input);
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
