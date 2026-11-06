// Reproducible native vector/type artwork export through installed Chrome.
import { chromium } from '@playwright/test';
import { readFile, writeFile } from 'node:fs/promises';
const assets = new URL('../src/aweb_naapp/assets/identity/', import.meta.url);
const font = await readFile(new URL('../src/aweb_naapp/assets/fonts/Archivo-Latin-Variable.woff2', import.meta.url));
const face = `@font-face{font-family:Archivo;src:url(data:font/woff2;base64,${font.toString('base64')});font-weight:400 900}`;
const browser = await chromium.launch({channel:'chrome'});
const page = await browser.newPage({deviceScaleFactor:1});
async function raster(svg, width, height, filename, solid=false) {
 await page.setViewportSize({width,height});
 await page.setContent(`<style>${face}html,body{margin:0;width:${width}px;height:${height}px;background:${solid?'#fff':'transparent'}}svg{display:block;width:100%;height:100%}</style>${svg}`);
 await page.evaluate(async()=>{await document.fonts.load('850 120px Archivo');await document.fonts.ready});
 await page.screenshot({path:new URL(filename,assets).pathname,omitBackground:!solid});
}
const icon=await readFile(new URL('favicon.svg',assets),'utf8');
for(const size of [16,32,48,180,192,512]) await raster(icon,size,size,`icon-${size}.png`,size>=180);
for(const brand of ['aweb','folio','library']) {
 // The vector sources retain native Archivo type; this exporter supplies the
 // licensed local face. Cards make no claim beyond the existing product name.
 const svg=`<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630"><rect width="1200" height="630" fill="#ffffff"/><g fill="none" stroke-width="9" transform="translate(84 230) scale(2)"><path stroke="#b76e17" d="M13 3 C12 17 21 22 43 22"/><path stroke="#17191c" d="M3 32 H43 M7 61 C16 47 25 42 43 42"/></g><text x="190" y="334" fill="#17191c" font-family="Archivo,Arial,sans-serif" font-weight="850" font-size="128" letter-spacing="-7">${brand}</text><g fill="none" stroke="#879ac4" stroke-width="2" stroke-dasharray="3 14" opacity=".32"><path d="M950 -50 C800 180 1300 220 1100 400 S700 500 700 700"/><path d="M970 -50 C820 180 1320 220 1120 400 S720 500 720 700"/><path stroke="#b76e17" d="M990 -50 C840 180 1340 220 1140 400 S740 500 740 700"/><path d="M1010 -50 C860 180 1360 220 1160 400 S760 500 760 700"/></g></svg>`;
 await writeFile(new URL(`${brand}-card.svg`,assets),svg+'\n');
 await raster(svg,1200,630,`${brand}-card.png`,true);
}
if(process.argv[2]) {
 await page.setViewportSize({width:720,height:300});
 const figures=await Promise.all([16,32,48,180].map(async size=>`<figure><img width="${size}" height="${size}" src="data:image/png;base64,${(await readFile(new URL(`icon-${size}.png`,assets))).toString('base64')}"><figcaption>${size} × ${size}</figcaption></figure>`));
 await page.setContent('<style>body{margin:0;font:16px Arial;background:#f0f2f5;color:#17191c;display:flex;align-items:center;justify-content:space-around;height:300px}figure{margin:0;text-align:center}img{display:block;margin:0 auto 20px}</style>'+figures.join(''));
 await page.screenshot({path:process.argv[2]});
}
await browser.close();
