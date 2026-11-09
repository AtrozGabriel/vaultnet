"use strict";
(() => {
    try {
        if (localStorage.getItem("vaultnet-theme") === "dark") document.documentElement.classList.add("dark");
    } catch (_) {}
    const menu = document.querySelector("[data-menu]");
    const sidebar = document.getElementById("sidebar");

    function closeMenu() {
        sidebar?.classList.remove("open");
        menu?.setAttribute("aria-expanded", "false");
        menu?.setAttribute("aria-label", "Abrir menu");
    }
    menu?.addEventListener("click", () => {
        const open = sidebar.classList.toggle("open");
        menu.setAttribute("aria-expanded", String(open));
        menu.setAttribute("aria-label", open ? "Fechar menu" : "Abrir menu");
    });
    document.addEventListener("click", event => {
        if (sidebar?.classList.contains("open") && !sidebar.contains(event.target) && !menu?.contains(event.target)) closeMenu();
    });
    document.addEventListener("keydown", event => {
        if (event.key === "Escape") closeMenu();
    });
    document.querySelector("[data-theme]")?.addEventListener("click", () => {
        const dark = document.documentElement.classList.toggle("dark");
        try {
            localStorage.setItem("vaultnet-theme", dark ? "dark" : "light");
        } catch (_) {}
    });
    document.querySelectorAll("[data-password]").forEach(button => button.addEventListener("click", () => {
        const input = document.getElementById(button.dataset.password);
        const visible = input.type === "password";
        input.type = visible ? "text" : "password";
        button.setAttribute("aria-pressed", String(visible));
        button.setAttribute("aria-label", visible ? "Ocultar senha" : "Mostrar senha");
    }));
    document.querySelectorAll("[data-copy]").forEach(button => button.addEventListener("click", async () => {
        const input = document.getElementById(button.dataset.copy);
        input.focus();
        input.select();
        if (!window.isSecureContext || !navigator.clipboard?.writeText) {
            button.textContent = "Selecione e copie";
            return;
        }
        try {
            await navigator.clipboard.writeText(input.value);
            button.textContent = "Copiado";
            setTimeout(() => {
                button.textContent = "Copiar";
            }, 1800);
        } catch (_) {
            button.textContent = "Selecione e copie";
        }
    }));
})();

(() => {
    const supported = new Set(["pdf", "png", "jpg", "jpeg", "txt", "csv"]);
    const mime = {pdf: "application/pdf", png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg"};
    const urls = new Set();
    const pdfCleanups = new WeakMap();
    function clear(box) {
        pdfCleanups.get(box)?.();
        pdfCleanups.delete(box);
        const content = box.querySelector("[data-preview-content]");
        content.querySelectorAll("[data-object-url]").forEach(node => {
            URL.revokeObjectURL(node.dataset.objectUrl);
            urls.delete(node.dataset.objectUrl);
        });
        content.replaceChildren();
    }
    async function render(box, blob, ext, current = () => true) {
        const content = box.querySelector("[data-preview-content]");
        if (ext === "txt" || ext === "csv") {
            const data = await blob.slice(0, 65536).arrayBuffer();
            if (!current()) return;
            let text;
            try { text = new TextDecoder("utf-8", {fatal: true}).decode(data); }
            catch (_) { text = new TextDecoder("windows-1252").decode(data); }
            const pre = document.createElement("pre");
            pre.textContent = text + (blob.size > 65536 ? "\n… Prévia limitada aos primeiros 64 KB." : "");
            content.append(pre);
            return;
        }
        if (!current()) return;
        if (ext === "pdf") {
            await renderPdf(box, blob, current);
            return;
        }
        const url = URL.createObjectURL(new Blob([blob], {type: mime[ext]}));
        urls.add(url);
        const node = document.createElement("img");
        node.dataset.objectUrl = url;
        node.alt = "Prévia da imagem selecionada";
        node.addEventListener("error", () => {
            box.querySelector("[data-preview-info]").textContent = "Não foi possível exibir a imagem.";
        });
        node.src = url;
        content.append(node);
    }
    async function renderPdf(box, blob, current) {
        const content = box.querySelector("[data-preview-content]");
        const base = new URL("static/pdfjs/", window.location.origin + "/");
        const pdfjs = await import(new URL("pdf.min.mjs", base).href);
        if (!current()) return;
        pdfjs.GlobalWorkerOptions.workerSrc = new URL("pdf.worker.min.mjs", base).href;
        const data = new Uint8Array(await blob.arrayBuffer());
        if (!current()) return;
        const task = pdfjs.getDocument({data, isEvalSupported: false, useWasm: false,
            cMapUrl: new URL("cmaps/", base).href, cMapPacked: true,
            standardFontDataUrl: new URL("standard_fonts/", base).href});
        let disposed = false, rendering = null, imageUrl = null;
        const cleanup = () => {
            disposed = true;
            rendering?.cancel();
            if (imageUrl) { URL.revokeObjectURL(imageUrl); urls.delete(imageUrl); }
            void task.destroy().catch(() => {});
        };
        pdfCleanups.set(box, cleanup);
        try {
            const pdf = await task.promise;
            if (disposed || !current()) { cleanup(); return; }
            const image = document.createElement("img");
            image.className = "pdf-page-image";
            const controls = document.createElement("div");
            controls.className = "pdf-page-controls";
            const prev = document.createElement("button"), next = document.createElement("button");
            for (const button of [prev, next]) {
                button.type = "button"; button.className = "button button-secondary button-small";
            }
            prev.textContent = "Página anterior"; next.textContent = "Próxima página";
            const label = document.createElement("span");
            label.setAttribute("role", "status");
            controls.append(prev, label, next);
            content.append(image, controls);
            let pageNumber = 1;
            async function showPage(number) {
                pageNumber = number;
                prev.disabled = next.disabled = true;
                label.textContent = "Carregando página…";
                let page;
                try {
                    page = await pdf.getPage(number);
                    if (disposed || !current()) return;
                    const natural = page.getViewport({scale: 1});
                    const scale = Math.min(2, 1500 / Math.max(natural.width, natural.height));
                    const viewport = page.getViewport({scale});
                    const canvas = document.createElement("canvas");
                    canvas.width = Math.ceil(viewport.width); canvas.height = Math.ceil(viewport.height);
                    rendering = page.render({canvasContext: canvas.getContext("2d"), viewport, background: "rgb(255,255,255)"});
                    await rendering.promise;
                    const png = await new Promise(resolve => canvas.toBlob(resolve, "image/png"));
                    canvas.width = canvas.height = 0;
                    if (disposed || !current()) return;
                    if (!png) throw new Error("Não foi possível gerar a imagem.");
                    if (imageUrl) { URL.revokeObjectURL(imageUrl); urls.delete(imageUrl); }
                    imageUrl = URL.createObjectURL(png); urls.add(imageUrl);
                    image.src = imageUrl; image.alt = `Página ${number} do PDF`;
                    pageNumber = number;
                    label.textContent = `Página ${number} de ${pdf.numPages}`;
                    prev.disabled = number === 1; next.disabled = number === pdf.numPages;
                } catch (error) {
                    if (!disposed && current()) {
                        label.textContent = "Não foi possível exibir esta página.";
                        prev.disabled = number <= 1; next.disabled = number >= pdf.numPages;
                        throw error;
                    }
                } finally { rendering = null; page?.cleanup(); }
            }
            prev.addEventListener("click", () => { void showPage(pageNumber - 1).catch(() => {}); });
            next.addEventListener("click", () => { void showPage(pageNumber + 1).catch(() => {}); });
            await showPage(1);
        } catch (error) {
            if (disposed || !current()) return;
            cleanup();
            content.replaceChildren();
            throw error;
        }
    }
    const input = document.getElementById("arquivo");
    const upload = document.querySelector("[data-upload-preview]");
    let selection = 0;
    input?.addEventListener("change", async () => {
        if (!upload) return;
        const version = ++selection;
        clear(upload);
        const file = input.files[0];
        upload.hidden = !file;
        if (!file) return;
        const ext = file.name.split(".").pop().toLowerCase();
        const info = upload.querySelector("[data-preview-info]");
        info.textContent = file.name + " · " + (file.size / 1024).toFixed(1) + " KB";
        if (!supported.has(ext)) {
            info.textContent += " — Prévia visual indisponível para este formato. Você pode enviar e baixar normalmente.";
            return;
        }
        try { await render(upload, file, ext, () => version === selection); }
        catch (_) { if (version === selection) info.textContent = "Não foi possível gerar a prévia deste arquivo."; }
    });
    document.querySelectorAll("[data-saved-preview]").forEach(async box => {
        const info = box.querySelector("[data-preview-info]");
        const ext = box.dataset.previewExtension;
        if (!supported.has(ext)) {
            info.textContent = "Prévia visual indisponível para este formato. Baixe o documento para abrir.";
            return;
        }
        try {
            const response = await fetch(box.dataset.previewUrl, {credentials: "same-origin", cache: "no-store"});
            if (!response.ok || response.redirected) throw new Error("preview");
            await render(box, await response.blob(), ext);
            info.textContent = box.dataset.previewName;
        } catch (_) {
            info.textContent = "Não foi possível carregar a prévia. Confira seu acesso ou tente novamente.";
        }
    });
    window.addEventListener("pagehide", event => { if (!event.persisted) urls.forEach(url => URL.revokeObjectURL(url)); });
})();

(() => {
    const mode = document.getElementById("visibilidade");
    const picker = document.querySelector("[data-recipient-picker]");
    if (!mode || !picker) return;
    const search = picker.querySelector("[data-recipient-search]");
    const rows = [...picker.querySelectorAll("[data-recipient-option]")];
    const status = picker.querySelector("[data-recipient-status]");
    const chosen = picker.querySelector("[data-recipient-selected]");
    const normalize = text => text.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLocaleLowerCase("pt-BR").trim();
    function filter() {
        const query = normalize(search.value);
        let total = 0;
        rows.forEach(row => {
            row.hidden = !normalize(row.dataset.recipientName).includes(query);
            if (!row.hidden) total++;
        });
        status.textContent = total ? `${total} usuário(s) encontrado(s). Selecione um abaixo.` : "Nenhum usuário encontrado.";
        const selected = rows.find(row => row.querySelector("input").checked);
        chosen.textContent = selected ? "Selecionado: " + selected.dataset.recipientName : "Nenhum usuário selecionado.";
        search.setCustomValidity(mode.value === "usuario" && !selected ? (rows.length ? "Selecione um usuário na lista." : "Não há usuários disponíveis. Escolha outro tipo de acesso.") : "");
    }
    function toggle(focus = false) {
        const active = mode.value === "usuario";
        picker.hidden = !active;
        search.disabled = !active;
        rows.forEach(row => {
            const radio = row.querySelector("input");
            radio.disabled = !active;
            radio.required = false;
        });
        filter();
        if (active && focus) search.focus();
    }
    mode.addEventListener("change", () => toggle(true));
    search.addEventListener("input", filter);
    picker.addEventListener("change", filter);
    mode.form?.addEventListener("reset", () => setTimeout(() => toggle(), 0));
    toggle();
})();

(() => {
    document.querySelectorAll('[data-toggle-panel]').forEach(button => {
        button.addEventListener('click', () => {
            const panel = document.getElementById(button.dataset.togglePanel);
            if (!panel) return;
            panel.hidden = !panel.hidden;
            button.setAttribute('aria-expanded', String(!panel.hidden));
            if (!panel.hidden) {
                panel.scrollIntoView({behavior: 'smooth', block: 'nearest'});
                panel.querySelector('input:not([type="hidden"]),select,button')?.focus({preventScroll: true});
            }
        });
    });
    const form = document.querySelector('[data-avatar-form]');
    if (!form) return;
    const input = form.querySelector('#avatar-arquivo');
    const editor = form.querySelector('[data-avatar-editor]');
    const canvas = form.querySelector('canvas');
    const ctx = canvas.getContext('2d');
    const zoom = form.querySelector('[data-avatar-zoom]');
    const x = form.querySelector('[data-avatar-x]');
    const y = form.querySelector('[data-avatar-y]');
    const status = form.querySelector('[data-avatar-status]');
    const save = form.querySelector('[data-avatar-save]');
    let photo = null, generation = 0;
    function draw() {
        if (!photo) return;
        const scale = Math.max(256 / photo.naturalWidth, 256 / photo.naturalHeight) * Number(zoom.value);
        const w = photo.naturalWidth * scale, h = photo.naturalHeight * scale;
        ctx.fillStyle = '#ffffff'; ctx.fillRect(0, 0, 256, 256);
        ctx.drawImage(photo, (256-w)/2 + Number(x.value)/100*(w-256)/2,
            (256-h)/2 + Number(y.value)/100*(h-256)/2, w, h);
    }
    [zoom, x, y].forEach(control => control.addEventListener('input', draw));
    input.addEventListener('change', async () => {
        const version = ++generation;
        photo = null; editor.hidden = true; save.disabled = true;
        const file = input.files[0];
        if (!file) { status.textContent = 'Escolha uma imagem para ajustar o enquadramento.'; return; }
        if (!['image/png','image/jpeg','image/webp'].includes(file.type) || file.size > 10*1024*1024) {
            status.textContent = 'Escolha PNG, JPG ou WebP de até 10 MB.'; return;
        }
        const url = URL.createObjectURL(file);
        try {
            const image = new Image(); image.src = url;
            await image.decode();
            if (version !== generation) return;
            if (image.naturalWidth * image.naturalHeight > 40000000) throw new Error('large');
            photo = image; zoom.value = '1'; x.value = y.value = '0';
            editor.hidden = false; save.disabled = false; draw();
            status.textContent = 'Ajuste o zoom e a posição. A prévia mostra o recorte que será salvo.';
        } catch (_) {
            if (version === generation) status.textContent = 'Não foi possível abrir a imagem. Tente uma imagem menor ou outro arquivo.';
        } finally { URL.revokeObjectURL(url); }
    });
    form.addEventListener('submit', async event => {
        event.preventDefault();
        if (!photo || save.disabled) return;
        save.disabled = true; input.disabled = true;
        [zoom,x,y].forEach(c => c.disabled = true);
        status.textContent = 'Salvando foto…';
        try {
            const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/png'));
            if (!blob) throw new Error('encode');
            const body = new FormData();
            body.set('csrf', form.querySelector('[name="csrf"]').value);
            body.set('foto', blob, 'perfil.png');
            const response = await fetch(form.action, {method: 'POST', body, credentials: 'same-origin'});
            const target = new URL(response.url);
            if (!response.ok || target.pathname !== '/perfil') throw new Error('save');
            window.location.assign(target.href);
        } catch (_) {
            status.textContent = 'Não foi possível salvar. Confira sua conexão e sessão, e tente novamente.';
            save.disabled = false;
        } finally { input.disabled = false; [zoom,x,y].forEach(c => c.disabled = false); }
    });
})();

(() => {
    const button = document.querySelector('[data-authorize-ip]');
    const field = document.getElementById('ips-publicos');
    if (!button || !field) return;
    button.addEventListener('click', () => {
        const ips = field.value.split(/[\s,]+/).filter(Boolean);
        if (!ips.includes(button.dataset.authorizeIp)) ips.push(button.dataset.authorizeIp);
        field.value = ips.join('\n');
        document.querySelector('[data-authorize-status]').textContent = 'IP adicionado à lista. Clique em Aplicar configuração para salvar.';
    });
})();
