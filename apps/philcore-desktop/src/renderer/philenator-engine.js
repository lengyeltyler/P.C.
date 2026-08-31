"use strict";

(function exposePhilenatorEngine(root) {
  const WIDTH = 420;
  const HEIGHT = 420;
  const ASSET_ROOT = "./assets/philenator/";
  const MANIFEST_PATH = `${ASSET_ROOT}manifest.json`;
  const BACKGROUND_TRAITS = new Set([
    "bgColor",
    "bgNebula",
    "bgStars",
    "bgSpiral",
    "bgDust",
    "bgOverlay"
  ]);
  const TRAIT_KEYS = Object.freeze([
    "bgColor",
    "bgNebula",
    "bgStars",
    "bgSpiral",
    "bgDust",
    "bgOverlay",
    "bodyBase",
    "body",
    "spikes",
    "teeth",
    "jawNose",
    "eyes",
    "top"
  ]);

  let manifestPromise;

  function randomUnit() {
    const value = new Uint32Array(1);
    root.crypto.getRandomValues(value);
    return value[0] / 0x1_0000_0000;
  }

  function randomInteger(minimum, maximum) {
    return minimum + Math.floor(randomUnit() * (maximum - minimum + 1));
  }

  function pick(values) {
    if (!Array.isArray(values) || values.length === 0) {
      throw new Error("PHILENATOR_EMPTY_TRAIT_SET");
    }
    return values[randomInteger(0, values.length - 1)];
  }

  function pickKey(value) {
    return pick(Object.keys(value));
  }

  function chance(probability) {
    return randomUnit() < probability;
  }

  function fileChoice(path) {
    const name = String(path).split("/").pop() || "unknown";
    return name.replace(/\.svg$/iu, "").slice(0, 32);
  }

  function compactFingerprint(values) {
    let hash = 0x811c9dc5;
    for (const character of values.join("|")) {
      hash ^= character.codePointAt(0);
      hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    return hash.toString(16).padStart(8, "0");
  }

  function safeTraitPath(path) {
    const value = String(path || "");
    if (!/^traits\/[A-Za-z0-9_./-]+\.svg$/u.test(value) || value.includes("..")) {
      throw new Error("PHILENATOR_TRAIT_PATH_INVALID");
    }
    return `${ASSET_ROOT}${value}`;
  }

  async function loadManifest() {
    if (!manifestPromise) {
      manifestPromise = root.fetch(MANIFEST_PATH, {
        cache: "no-store",
        credentials: "same-origin"
      }).then((response) => {
        if (!response.ok) throw new Error(`PHILENATOR_MANIFEST_HTTP_${response.status}`);
        return response.json();
      }).then((manifest) => {
        for (const key of [
          "BgColor", "BgNebula", "BgStars", "BgSpiral", "BgDust", "BgOverlay",
          "BodyBase", "Body", "Spikes", "Teeth", "JawNose", "Eyes1", "Eyes2",
          "Eyes3", "Top"
        ]) {
          if (!manifest?.[key]) throw new Error(`PHILENATOR_MANIFEST_MISSING_${key}`);
        }
        return Object.freeze(manifest);
      });
    }
    return manifestPromise;
  }

  function layerPlan(manifest) {
    const layers = [];
    const traits = Object.fromEntries(TRAIT_KEYS.map((key) => [key, "none"]));
    const add = (trait, files) => {
      const normalized = files.map(String);
      layers.push(Object.freeze({ trait, files: Object.freeze(normalized) }));
      traits[trait] = normalized.length === 1
        ? fileChoice(normalized[0])
        : `${normalized.length}-${compactFingerprint(normalized)}`;
    };

    add("bgColor", [pick(manifest.BgColor)]);
    if (chance(0.5)) {
      const style = pickKey(manifest.BgNebula);
      add("bgNebula", [pick(manifest.BgNebula[style])]);
    }
    if (chance(0.5)) add("bgStars", [pick(manifest.BgStars)]);
    if (chance(0.5)) {
      const style = pickKey(manifest.BgSpiral);
      add("bgSpiral", [pick(manifest.BgSpiral[style])]);
    }
    if (chance(0.5)) add("bgDust", [pick(manifest.BgDust)]);

    const overlays = [];
    for (let index = 0; index < randomInteger(0, 6); index += 1) {
      const opacity = pickKey(manifest.BgOverlay);
      overlays.push(pick(manifest.BgOverlay[opacity]));
    }
    if (overlays.length > 0) add("bgOverlay", overlays);

    add("bodyBase", [pick(manifest.BodyBase)]);
    if (chance(0.5)) {
      const style = pickKey(manifest.Body);
      add("body", [pick(manifest.Body[style])]);
    }
    if (chance(0.5)) {
      const style = pickKey(manifest.Spikes);
      add("spikes", [pick(manifest.Spikes[style])]);
    }

    const jawStyle = pickKey(manifest.JawNose);
    if (chance(0.5)) add("teeth", [pick(manifest.Teeth[jawStyle])]);
    add("jawNose", [pick(manifest.JawNose[jawStyle])]);

    const eyeStyle = pick(["1", "2", "3"]);
    if (eyeStyle === "1") {
      add("eyes", [pick(manifest.Eyes1)]);
    } else {
      const eyeSet = manifest[`Eyes${eyeStyle}`];
      add("eyes", [pick(eyeSet.Frame), pick(eyeSet.Lens)]);
    }

    if (chance(0.5)) {
      const style = pickKey(manifest.Top);
      add("top", [pick(manifest.Top[style])]);
    }

    return Object.freeze({
      layers: Object.freeze(layers),
      traits: Object.freeze(traits)
    });
  }

  function svgImageHref(svg) {
    const bytes = new TextEncoder().encode(svg);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return `data:image/svg+xml;base64,${root.btoa(binary)}`;
  }

  function compose(hrefs) {
    const images = hrefs.map((href) =>
      `<image href="${href}" x="0" y="0" width="${WIDTH}" height="${HEIGHT}"/>`
    ).join("");
    return `<svg xmlns="http://www.w3.org/2000/svg" width="${WIDTH}" height="${HEIGHT}" viewBox="0 0 ${WIDTH} ${HEIGHT}">${images}</svg>`;
  }

  async function fetchTrait(path) {
    const response = await root.fetch(safeTraitPath(path), {
      cache: "force-cache",
      credentials: "same-origin"
    });
    if (!response.ok) throw new Error(`PHILENATOR_TRAIT_HTTP_${response.status}`);
    const svg = await response.text();
    if (!/^\s*(?:<\?xml[^>]*>\s*)?<svg[\s>]/iu.test(svg)
      || /<script|<foreignObject|javascript:|\son\w+\s*=/iu.test(svg)) {
      throw new Error("PHILENATOR_TRAIT_SVG_UNSAFE");
    }
    return svgImageHref(svg);
  }

  async function generate() {
    const manifest = await loadManifest();
    const plan = layerPlan(manifest);
    const rendered = [];
    for (const layer of plan.layers) {
      for (const file of layer.files) {
        rendered.push(Object.freeze({ trait: layer.trait, href: await fetchTrait(file) }));
      }
    }
    const background = rendered
      .filter((layer) => BACKGROUND_TRAITS.has(layer.trait))
      .map((layer) => layer.href);
    if (background.length === 0) throw new Error("PHILENATOR_BACKGROUND_MISSING");
    return Object.freeze({
      version: "philenator-v2-local-1",
      sourceCommit: "f174dedda16a354c592e3252d9b0b5805bab59c4",
      traits: plan.traits,
      layers: TRAIT_KEYS,
      svg: compose(rendered.map((layer) => layer.href)),
      backgroundSvg: compose(background)
    });
  }

  root.PhilenatorEngine = Object.freeze({
    generate,
    layerOrder: TRAIT_KEYS,
    sourceCommit: "f174dedda16a354c592e3252d9b0b5805bab59c4"
  });
}(globalThis));
