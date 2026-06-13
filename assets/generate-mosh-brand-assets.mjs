import fs from "node:fs/promises";
import path from "node:path";

const OUT = path.join(process.cwd(), "brand");

const P = {
  BLACK: "#0D0F12",
  CHARCOAL: "#2A2E33",
  WHITE: "#FFFFFF",
  ORANGE: "#FF5A1F",
  RED: "#D92027",
  GRAY: "#8A9099",
  SOFT: "#F6F7F8",
};

async function ensureDir(filePath) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
}

async function write(rel, content) {
  const file = path.join(OUT, rel);
  await ensureDir(file);
  await fs.writeFile(file, content.trim() + "\n", "utf8");
}

function svg({ w, h, title, bg, content }) {
  return `
<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" fill="none" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="${title}">
  <title>${title}</title>
  ${bg ? `<rect width="${w}" height="${h}" fill="${bg}"/>` : ""}
  ${content}
</svg>`;
}

function moshMark({ left = P.BLACK, right = P.ORANGE, harness = P.ORANGE } = {}) {
  return `
<g id="mmosh-mark">
  <!-- Split abstract M silhouette.
       Two filled halves create a clear center split and a lower center point. -->

  <path
    d="M92 390
       L92 112
       L256 248
       L256 340
       L158 258
       L158 390
       Z"
    fill="${left}"
  />

  <path
    d="M256 248
       L420 112
       L420 390
       L354 390
       L354 258
       L256 340
       Z"
    fill="${right}"
  />

  <!-- Perspective harness path / controlled execution steps.
       Wider toward the viewer, like a zebra crossing in perspective. -->

  <path d="M226 358H286L300 378H212L226 358Z" fill="${harness}"/>
  <path d="M206 398H306L326 426H186L206 398Z" fill="${harness}"/>
  <path d="M184 442H328L354 474H158L184 442Z" fill="${harness}"/>
</g>`;
}

function iconSvg({ mode }) {
  const dark = mode === "dark";
  const monoBlack = mode === "mono-black";
  const monoWhite = mode === "mono-white";

  const left = monoBlack ? P.BLACK : monoWhite ? P.WHITE : dark ? P.WHITE : P.BLACK;
  const right = monoBlack ? P.BLACK : monoWhite ? P.WHITE : P.ORANGE;
  const harness = monoBlack ? P.BLACK : monoWhite ? P.WHITE : P.ORANGE;

  return svg({
    w: 512,
    h: 512,
    title: `mosh icon ${mode}`,
    content: moshMark({ left, right, harness }),
  });
}

function faviconSvg() {
  return svg({
    w: 512,
    h: 512,
    title: "mosh favicon",
    bg: "transparent",
    content: `
<rect x="36" y="36" width="440" height="440" rx="92" fill="${P.BLACK}"/>
${moshMark({ left: P.WHITE, right: P.ORANGE, harness: P.ORANGE })}`,
  });
}

function horizontalLogoSvg({ mode, background = false, subtitle = true }) {
  const dark = mode === "dark";
  const bg = background ? (dark ? P.BLACK : P.WHITE) : undefined;
  const text = dark ? P.WHITE : P.BLACK;
  const sub = dark ? "#C9CED6" : P.CHARCOAL;
  const left = dark ? P.WHITE : P.BLACK;

  return svg({
    w: 1320,
    h: 420,
    title: `mosh horizontal logo ${mode}`,
    bg,
    content: `
<g transform="translate(44 30) scale(0.66)">
  ${moshMark({ left, right: P.ORANGE, harness: P.ORANGE })}
</g>

<text x="410" y="210"
  fill="${text}"
  font-family="Space Grotesk, Sora, Inter, Arial, sans-serif"
  font-size="146"
  font-weight="800"
  letter-spacing="5">mosh</text>

${
  subtitle
    ? `<text x="418" y="270"
  fill="${sub}"
  font-family="JetBrains Mono, IBM Plex Mono, Menlo, monospace"
  font-size="26"
  font-weight="600"
  letter-spacing="1.6">MODEL-DRIVEN OPEN SECURITY HARNESS</text>`
    : ""
}`,
  });
}

function wordmarkSvg({ mode }) {
  const dark = mode === "dark";
  const monoBlack = mode === "mono-black";
  const monoWhite = mode === "mono-white";
  const fill = monoBlack ? P.BLACK : monoWhite ? P.WHITE : dark ? P.WHITE : P.BLACK;

  return svg({
    w: 650,
    h: 180,
    title: `mosh wordmark ${mode}`,
    content: `
<text x="16" y="126"
  fill="${fill}"
  font-family="Space Grotesk, Sora, Inter, Arial, sans-serif"
  font-size="132"
  font-weight="800"
  letter-spacing="5">mosh</text>`,
  });
}

function readmeHeaderSvg() {
  return svg({
    w: 1600,
    h: 640,
    title: "mosh GitHub README header",
    bg: P.BLACK,
    content: `
<defs>
  <radialGradient id="glow" cx="75%" cy="48%" r="55%">
    <stop offset="0%" stop-color="${P.ORANGE}" stop-opacity="0.22"/>
    <stop offset="58%" stop-color="${P.ORANGE}" stop-opacity="0.06"/>
    <stop offset="100%" stop-color="${P.BLACK}" stop-opacity="0"/>
  </radialGradient>
</defs>

<rect width="1600" height="640" fill="url(#glow)"/>

<g opacity="0.46" stroke="${P.ORANGE}" stroke-width="3" fill="none">
  <path d="M760 320C900 320 930 230 1060 230H1470"/>
  <path d="M760 360C940 360 970 430 1110 430H1490"/>
  <path d="M760 280C900 280 940 170 1100 170H1450"/>
  <path d="M760 400C900 400 950 520 1110 520H1430"/>
  <path d="M760 240H940C1020 240 1070 310 1170 310H1490"/>
</g>

<g fill="${P.ORANGE}">
  <circle cx="1060" cy="230" r="8"/>
  <circle cx="1110" cy="430" r="8"/>
  <circle cx="1100" cy="170" r="8"/>
  <circle cx="1110" cy="520" r="8"/>
  <circle cx="1170" cy="310" r="8"/>
  <circle cx="1470" cy="230" r="6"/>
  <circle cx="1490" cy="430" r="6"/>
  <circle cx="1450" cy="170" r="6"/>
  <circle cx="1430" cy="520" r="6"/>
  <circle cx="1490" cy="310" r="6"/>
</g>

<g transform="translate(80 82) scale(0.60)">
  ${moshMark({ left: P.WHITE, right: P.ORANGE, harness: P.ORANGE })}
</g>

<text x="390" y="245"
  fill="${P.WHITE}"
  font-family="Space Grotesk, Sora, Inter, Arial, sans-serif"
  font-size="150"
  font-weight="800"
  letter-spacing="5">mosh</text>

<text x="400" y="305"
  fill="#C9CED6"
  font-family="JetBrains Mono, IBM Plex Mono, Menlo, monospace"
  font-size="25"
  font-weight="600"
  letter-spacing="1.5">MODEL-DRIVEN OPEN SECURITY HARNESS</text>

<text x="82" y="505"
  fill="${P.ORANGE}"
  font-family="JetBrains Mono, IBM Plex Mono, Menlo, monospace"
  font-size="26"
  font-weight="600">Security testing. Driven by models. Grounded in evidence.</text>`,
  });
}

function openGraphSvg() {
  return svg({
    w: 1200,
    h: 630,
    title: "mosh social preview card",
    bg: P.BLACK,
    content: `
<defs>
  <radialGradient id="ogGlow" cx="76%" cy="48%" r="60%">
    <stop offset="0%" stop-color="${P.ORANGE}" stop-opacity="0.24"/>
    <stop offset="64%" stop-color="${P.ORANGE}" stop-opacity="0.07"/>
    <stop offset="100%" stop-color="${P.BLACK}" stop-opacity="0"/>
  </radialGradient>
</defs>
<rect width="1200" height="630" fill="url(#ogGlow)"/>

<g opacity="0.42" stroke="${P.ORANGE}" stroke-width="3" fill="none">
  <path d="M610 300C720 300 760 210 870 210H1120"/>
  <path d="M610 350C760 350 785 430 905 430H1110"/>
  <path d="M610 250H740C825 250 850 310 930 310H1130"/>
</g>

<g fill="${P.ORANGE}">
  <circle cx="870" cy="210" r="8"/>
  <circle cx="905" cy="430" r="8"/>
  <circle cx="930" cy="310" r="8"/>
</g>

<g transform="translate(72 104) scale(0.56)">
  ${moshMark({ left: P.WHITE, right: P.ORANGE, harness: P.ORANGE })}
</g>

<text x="350" y="300"
  fill="${P.WHITE}"
  font-family="Space Grotesk, Sora, Inter, Arial, sans-serif"
  font-size="134"
  font-weight="800"
  letter-spacing="5">mosh</text>

<text x="360" y="356"
  fill="#C9CED6"
  font-family="JetBrains Mono, IBM Plex Mono, Menlo, monospace"
  font-size="24"
  font-weight="600"
  letter-spacing="1.4">MODEL-DRIVEN OPEN SECURITY HARNESS</text>

<text x="76" y="510"
  fill="${P.ORANGE}"
  font-family="JetBrains Mono, IBM Plex Mono, Menlo, monospace"
  font-size="25"
  font-weight="700">Controlled chaos for application security testing.</text>`,
  });
}

function usageGuideSvg() {
  return svg({
    w: 1600,
    h: 1000,
    title: "mosh one-page usage guide",
    bg: P.SOFT,
    content: `
<text x="72" y="90" fill="${P.BLACK}" font-family="Space Grotesk, Sora, Inter, Arial, sans-serif" font-size="54" font-weight="800">mosh brand usage guide</text>
<text x="72" y="134" fill="${P.CHARCOAL}" font-family="Inter, Arial, sans-serif" font-size="24">Controlled chaos for application security testing.</text>

<rect x="72" y="190" width="680" height="250" rx="24" fill="${P.BLACK}"/>
<g transform="translate(120 216) scale(0.38)">
  ${moshMark({ left: P.WHITE, right: P.ORANGE, harness: P.ORANGE })}
</g>
<text x="335" y="345" fill="${P.WHITE}" font-family="Space Grotesk, Sora, Inter, Arial, sans-serif" font-size="94" font-weight="800" letter-spacing="3">mosh</text>
<text x="340" y="385" fill="#C9CED6" font-family="JetBrains Mono, Menlo, monospace" font-size="19" font-weight="600">MODEL-DRIVEN OPEN SECURITY HARNESS</text>

<rect x="832" y="190" width="316" height="250" rx="24" fill="${P.WHITE}" stroke="#D9DDE4"/>
<g transform="translate(885 216) scale(0.38)">
  ${moshMark({ left: P.BLACK, right: P.ORANGE, harness: P.ORANGE })}
</g>

<rect x="1210" y="190" width="316" height="250" rx="24" fill="${P.BLACK}"/>
<g transform="translate(1263 216) scale(0.38)">
  ${moshMark({ left: P.WHITE, right: P.WHITE, harness: P.WHITE })}
</g>

<text x="72" y="520" fill="${P.BLACK}" font-family="Space Grotesk, Sora, Inter, Arial, sans-serif" font-size="34" font-weight="800">Palette</text>

<rect x="72" y="555" width="120" height="80" rx="14" fill="${P.BLACK}" stroke="#CBD0D8"/>
<text x="72" y="670" fill="${P.CHARCOAL}" font-family="JetBrains Mono, Menlo, monospace" font-size="18">${P.BLACK}</text>
<text x="72" y="698" fill="${P.GRAY}" font-family="Inter, Arial, sans-serif" font-size="17">Near black</text>

<rect x="302" y="555" width="120" height="80" rx="14" fill="${P.CHARCOAL}" stroke="#CBD0D8"/>
<text x="302" y="670" fill="${P.CHARCOAL}" font-family="JetBrains Mono, Menlo, monospace" font-size="18">${P.CHARCOAL}</text>
<text x="302" y="698" fill="${P.GRAY}" font-family="Inter, Arial, sans-serif" font-size="17">Charcoal</text>

<rect x="532" y="555" width="120" height="80" rx="14" fill="${P.WHITE}" stroke="#CBD0D8"/>
<text x="532" y="670" fill="${P.CHARCOAL}" font-family="JetBrains Mono, Menlo, monospace" font-size="18">${P.WHITE}</text>
<text x="532" y="698" fill="${P.GRAY}" font-family="Inter, Arial, sans-serif" font-size="17">White</text>

<rect x="762" y="555" width="120" height="80" rx="14" fill="${P.ORANGE}" stroke="#CBD0D8"/>
<text x="762" y="670" fill="${P.CHARCOAL}" font-family="JetBrains Mono, Menlo, monospace" font-size="18">${P.ORANGE}</text>
<text x="762" y="698" fill="${P.GRAY}" font-family="Inter, Arial, sans-serif" font-size="17">Signal orange</text>

<rect x="992" y="555" width="120" height="80" rx="14" fill="${P.RED}" stroke="#CBD0D8"/>
<text x="992" y="670" fill="${P.CHARCOAL}" font-family="JetBrains Mono, Menlo, monospace" font-size="18">${P.RED}</text>
<text x="992" y="698" fill="${P.GRAY}" font-family="Inter, Arial, sans-serif" font-size="17">Deep red</text>

<rect x="1222" y="555" width="120" height="80" rx="14" fill="${P.GRAY}" stroke="#CBD0D8"/>
<text x="1222" y="670" fill="${P.CHARCOAL}" font-family="JetBrains Mono, Menlo, monospace" font-size="18">${P.GRAY}</text>
<text x="1222" y="698" fill="${P.GRAY}" font-family="Inter, Arial, sans-serif" font-size="17">Cool gray</text>

<text x="72" y="790" fill="${P.BLACK}" font-family="Space Grotesk, Sora, Inter, Arial, sans-serif" font-size="34" font-weight="800">Usage rules</text>

<text x="72" y="840" fill="${P.CHARCOAL}" font-family="Inter, Arial, sans-serif" font-size="24">Do: use strong contrast, preserve proportions, keep clear space, use SVG for web/docs.</text>
<text x="72" y="882" fill="${P.CHARCOAL}" font-family="Inter, Arial, sans-serif" font-size="24">Don’t: stretch, skew, rotate, recolor randomly, add effects, or place on busy backgrounds.</text>
<text x="72" y="924" fill="${P.CHARCOAL}" font-family="Inter, Arial, sans-serif" font-size="24">Typography: Space Grotesk or Sora for brand; JetBrains Mono for CLI/documentation accents.</text>

<text x="1040" y="790" fill="${P.BLACK}" font-family="Space Grotesk, Sora, Inter, Arial, sans-serif" font-size="34" font-weight="800">Clear space</text>
<rect x="1040" y="820" width="360" height="120" rx="18" fill="${P.WHITE}" stroke="#CBD0D8" stroke-dasharray="8 8"/>
<g transform="translate(1168 800) scale(0.22)">
  ${moshMark({ left: P.BLACK, right: P.ORANGE, harness: P.ORANGE })}
</g>
<text x="1040" y="972" fill="${P.GRAY}" font-family="Inter, Arial, sans-serif" font-size="18">Use generous padding around the mark, especially in app icons.</text>`,
  });
}

function usageGuideMd() {
  return `
# mosh brand usage guide

## Core idea

**Controlled chaos for application security testing.**

The mosh mark uses a sharp split **M** with an internal perspective harness path. The icon should feel technical, contained, high-energy, and credible for open-source security tooling.

## Palette

| Token | Hex |
|---|---|
| Near black | ${P.BLACK} |
| Charcoal | ${P.CHARCOAL} |
| White | ${P.WHITE} |
| Signal orange | ${P.ORANGE} |
| Deep red | ${P.RED} |
| Cool gray | ${P.GRAY} |

## Typography

Recommended:

- **Space Grotesk** for logo-adjacent headings and UI branding.
- **Sora** as an alternate geometric brand face.
- **JetBrains Mono** for CLI examples, docs, and technical captions.

## Use

Use SVG files for GitHub, websites, documentation, READMEs, and package registries. Use PNG exports for social cards, app icons, and platforms that do not support SVG.

## Avoid

Do not stretch, skew, rotate, recolor randomly, add shadows, add gradients, or place the logo over busy imagery.
`;
}

async function exportPngs() {
  let sharp;

  try {
    sharp = (await import("sharp")).default;
  } catch {
    console.log("SVG files created. Install sharp to generate PNG exports: npm install sharp png-to-ico");
    return;
  }

  async function png(srcRel, destRel, width, height) {
    const src = path.join(OUT, srcRel);
    const dest = path.join(OUT, destRel);
    await ensureDir(dest);

    let pipeline = sharp(src);

    if (width && height) {
      pipeline = pipeline.resize(width, height, {
        fit: "contain",
        background: { r: 0, g: 0, b: 0, alpha: 0 },
      });
    } else if (width) {
      pipeline = pipeline.resize({ width });
    }

    await pipeline.png().toFile(dest);
  }

  const sizes = [16, 32, 48, 64, 128, 256, 512, 1024];

  for (const size of sizes) {
    await png("favicon/favicon.svg", `png/icon/icon-${size}.png`, size, size);
  }

  await png("favicon/favicon.svg", "favicon/apple-touch-icon.png", 180, 180);
  await png("favicon/favicon.svg", "png/social/github-avatar.png", 512, 512);

  await png("svg/mmosh-logo-horizontal-light.svg", "png/logo/logo-horizontal-light-transparent.png", 1200);
  await png("svg/mmosh-logo-horizontal-dark.svg", "png/logo/logo-horizontal-dark-transparent.png", 1200);
  await png("svg/mmosh-logo-horizontal-on-light.svg", "png/logo/logo-horizontal-on-light.png", 1200);
  await png("svg/mmosh-logo-horizontal-on-dark.svg", "png/logo/logo-horizontal-on-dark.png", 1200);

  await png("svg/mmosh-wordmark-light.svg", "png/logo/wordmark-light-transparent.png", 900);
  await png("svg/mmosh-wordmark-dark.svg", "png/logo/wordmark-dark-transparent.png", 900);

  await png("svg/mmosh-icon-light.svg", "png/icon/icon-light-transparent.png", 1024, 1024);
  await png("svg/mmosh-icon-dark.svg", "png/icon/icon-dark-transparent.png", 1024, 1024);

  await png("social/mmosh-readme-header.svg", "png/social/readme-header.png", 1600, 640);
  await png("social/mmosh-open-graph-card.svg", "png/social/open-graph-card.png", 1200, 630);
  await png("usage-guide/mmosh-usage-guide.svg", "usage-guide/mmosh-usage-guide.png", 1600, 1000);

  try {
    const pngToIco = (await import("png-to-ico")).default;
    const ico = await pngToIco([
      path.join(OUT, "png/icon/icon-16.png"),
      path.join(OUT, "png/icon/icon-32.png"),
      path.join(OUT, "png/icon/icon-48.png"),
    ]);
    await fs.writeFile(path.join(OUT, "favicon/favicon.ico"), ico);
  } catch {
    console.log("PNG exports created. Install png-to-ico for favicon.ico: npm install png-to-ico");
  }
}

async function main() {
  await fs.rm(OUT, { recursive: true, force: true });

  await write("svg/mmosh-icon-dark.svg", iconSvg({ mode: "dark" }));
  await write("svg/mmosh-icon-light.svg", iconSvg({ mode: "light" }));
  await write("svg/mmosh-icon-mono-black.svg", iconSvg({ mode: "mono-black" }));
  await write("svg/mmosh-icon-mono-white.svg", iconSvg({ mode: "mono-white" }));

  await write("svg/mmosh-logo-horizontal-dark.svg", horizontalLogoSvg({ mode: "dark", background: false }));
  await write("svg/mmosh-logo-horizontal-light.svg", horizontalLogoSvg({ mode: "light", background: false }));
  await write("svg/mmosh-logo-horizontal-on-dark.svg", horizontalLogoSvg({ mode: "dark", background: true }));
  await write("svg/mmosh-logo-horizontal-on-light.svg", horizontalLogoSvg({ mode: "light", background: true }));

  await write("svg/mmosh-wordmark-dark.svg", wordmarkSvg({ mode: "dark" }));
  await write("svg/mmosh-wordmark-light.svg", wordmarkSvg({ mode: "light" }));
  await write("svg/mmosh-wordmark-mono-black.svg", wordmarkSvg({ mode: "mono-black" }));
  await write("svg/mmosh-wordmark-mono-white.svg", wordmarkSvg({ mode: "mono-white" }));

  await write("favicon/favicon.svg", faviconSvg());
  await write("social/mmosh-readme-header.svg", readmeHeaderSvg());
  await write("social/mmosh-open-graph-card.svg", openGraphSvg());
  await write("usage-guide/mmosh-usage-guide.svg", usageGuideSvg());
  await write("usage-guide/mmosh-usage-guide.md", usageGuideMd());

  await exportPngs();

  console.log("mosh brand kit generated in ./brand");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
