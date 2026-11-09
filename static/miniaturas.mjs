async function pdfThumbnail(url) {
    const base = new URL("./pdfjs/", import.meta.url);
    const pdfjs = await import(new URL("pdf.min.mjs", base));
    pdfjs.GlobalWorkerOptions.workerSrc = new URL("pdf.worker.min.mjs", base).href;
    const response = await fetch(url, {cache: "no-store", signal: AbortSignal.timeout(15000)});
    if (!response.ok || response.redirected) return null;
    const task = pdfjs.getDocument({
        data: new Uint8Array(await response.arrayBuffer()),
        isEvalSupported: false,
        useWasm: false,
        cMapUrl: new URL("cmaps/", base).href,
        cMapPacked: true,
        standardFontDataUrl: new URL("standard_fonts/", base).href,
    });
    try {
        const page = await (await task.promise).getPage(1);
        const original = page.getViewport({scale: 1});
        const viewport = page.getViewport({scale: Math.min(68 / original.width, 76 / original.height)});
        const canvas = document.createElement("canvas");
        canvas.width = Math.ceil(viewport.width);
        canvas.height = Math.ceil(viewport.height);
        canvas.setAttribute("aria-hidden", "true");
        await page.render({canvasContext: canvas.getContext("2d"), viewport}).promise;
        return canvas;
    } finally {
        await task.destroy();
    }
}

async function loadThumbnail(link) {
    const {thumbnailUrl, thumbnailType} = link.dataset;
    if (thumbnailType === "pdf") {
        const canvas = await pdfThumbnail(thumbnailUrl);
        if (canvas) link.replaceChildren(canvas);
        return;
    }
    const image = new Image();
    image.alt = "";
    image.src = thumbnailUrl;
    await image.decode();
    link.replaceChildren(image);
}

if ("IntersectionObserver" in window) {
    const observer = new IntersectionObserver(entries => {
        for (const entry of entries) {
            if (!entry.isIntersecting) continue;
            observer.unobserve(entry.target);
            // Keep the file icon if the preview cannot be loaded.
            void loadThumbnail(entry.target).catch(() => {});
        }
    });
    document.querySelectorAll("[data-thumbnail-url]").forEach(link => observer.observe(link));
}
