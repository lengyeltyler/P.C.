(function exposePhilPreviewProvider(root) {
  const layerOrder = Object.freeze([
    "bgColor", "bgNebula", "bgStars", "bgSpiral", "bgDust", "bgOverlay",
    "bodyBase", "body", "spikes", "teeth", "jawNose", "eyes", "top"
  ]);
  const poses = Object.freeze([
    Object.freeze({ id: "idle", file: "phil_idle.png", alt: "Phil standing ready" }),
    Object.freeze({ id: "wave", file: "phil_wave.png", alt: "Phil waving hello" }),
    Object.freeze({ id: "curious", file: "phil_curious_review.png", alt: "Phil reviewing a request" }),
    Object.freeze({ id: "working", file: "phil_working_focus.png", alt: "Phil focused on a protected task" }),
    Object.freeze({ id: "success", file: "phil_success_jump.png", alt: "Phil celebrating a successful check" }),
    Object.freeze({ id: "waiting", file: "phil_waiting.png", alt: "Phil waiting for your decision" }),
    Object.freeze({ id: "walk", file: "phil_walk_right.png", alt: "Phil walking toward the next step" }),
    Object.freeze({ id: "run", file: "phil_run_right.png", alt: "Phil running toward the next step" }),
    Object.freeze({ id: "crouch", file: "phil_crouch.png", alt: "Phil staying alert" }),
    Object.freeze({ id: "rest", file: "phil_seated_rest.png", alt: "Phil resting beside your identity" }),
    Object.freeze({ id: "tired", file: "phil_failed_tired.png", alt: "Phil showing that a request stopped safely" }),
    Object.freeze({ id: "sleep", file: "phil_sleep.png", alt: "Phil sleeping while the identity is locked" })
  ]);

  function normalizeIndex(value) {
    const parsed = Number.parseInt(String(value ?? "0"), 10);
    if (!Number.isFinite(parsed)) return 0;
    return ((parsed % 100) + 100) % 100;
  }

  function selectionId(sequence) {
    return `local-philenator-${String(normalizeIndex(sequence) % 100).padStart(2, "0")}`;
  }

  function cacheKey(sequence) {
    return `philcore.philenator.preview.v2.${selectionId(sequence)}`;
  }

  function svgUri(svg) {
    return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
  }

  function pendingTraits() {
    return Object.fromEntries(layerOrder.map((layer) => [layer, `${layer}-pending`.slice(0, 32)]));
  }

  function isCurrentStoredPreview(stored) {
    return stored?.source === "philenator-local"
      && stored?.artworkSource === "philenator-local"
      && stored?.traits
      && layerOrder.every((layer) => typeof stored.traits[layer] === "string");
  }

  function fallbackPreview(sequence = 0, storedTraits = null) {
    const normalized = normalizeIndex(sequence);
    const pose = poses[normalized % poses.length];
    const traits = storedTraits && layerOrder.every((layer) => typeof storedTraits[layer] === "string")
      ? storedTraits
      : pendingTraits();
    return Object.freeze({
      selectionId: selectionId(normalized),
      sequence: normalized,
      traits: Object.freeze({ ...traits }),
      source: "philenator-local",
      artworkSource: "philenator-local",
      generatorRevision: "f174dedda16a354c592e3252d9b0b5805bab59c4",
      mintStatus: "not-minted",
      publicToken: null,
      imageUri: `./assets/characters/phil/${pose.file}`,
      backgroundUri: null,
      alt: pose.alt,
      generated: false
    });
  }

  function previewFromGenerated(sequence, generated) {
    const normalized = normalizeIndex(sequence);
    const value = Object.freeze({
      selectionId: selectionId(normalized),
      sequence: normalized,
      traits: Object.freeze({ ...generated.traits }),
      source: "philenator-local",
      artworkSource: "philenator-local",
      generatorRevision: generated.sourceCommit,
      mintStatus: "not-minted",
      publicToken: null,
      imageUri: svgUri(generated.svg),
      backgroundUri: svgUri(generated.backgroundSvg),
      alt: "A locally generated Phil made with Philenator",
      generated: true
    });
    try {
      root.localStorage?.setItem(cacheKey(normalized), JSON.stringify({
        svg: generated.svg,
        backgroundSvg: generated.backgroundSvg,
        traits: generated.traits,
        generatorRevision: generated.sourceCommit
      }));
    } catch {}
    return value;
  }

  function readCached(sequence, storedTraits = null) {
    try {
      const cached = JSON.parse(root.localStorage?.getItem(cacheKey(sequence)) || "null");
      if (!cached || typeof cached.svg !== "string" || typeof cached.backgroundSvg !== "string") return null;
      if (!cached.svg.includes("<svg") || !cached.backgroundSvg.includes("<svg")) return null;
      if (!cached.traits || !layerOrder.every((layer) => typeof cached.traits[layer] === "string")) return null;
      if (storedTraits && layerOrder.some((layer) => cached.traits[layer] !== storedTraits[layer])) return null;
      return previewFromGenerated(sequence, {
        ...cached,
        sourceCommit: cached.generatorRevision || root.PhilenatorEngine?.sourceCommit
      });
    } catch {
      return null;
    }
  }

  async function generatePreview(sequence) {
    if (!root.PhilenatorEngine?.generate) throw new Error("PHILENATOR_ENGINE_UNAVAILABLE");
    const generated = await root.PhilenatorEngine.generate();
    if (!layerOrder.every((layer) => generated.layers.includes(layer))) {
      throw new Error("PHILENATOR_LAYER_CONTRACT_INCOMPLETE");
    }
    return previewFromGenerated(sequence, generated);
  }

  const localProvider = Object.freeze({
    providerId: "philenator-v2-local-f174ded",
    source: "philenator-local",
    remoteAccessEnabled: false,
    defaultPreview: () => readCached(0) || fallbackPreview(0),
    ensure: async (current) => current?.generated ? current : generatePreview(current?.sequence ?? 0),
    randomize: async (current) => generatePreview(normalizeIndex(current?.sequence) + 1),
    fromStored: (stored) => {
      if (!isCurrentStoredPreview(stored)) return fallbackPreview(stored?.sequence ?? 0);
      return readCached(stored.sequence, stored.traits) || fallbackPreview(stored.sequence, stored.traits);
    }
  });

  root.PhilPreviewProvider = Object.freeze({
    localProvider,
    layerOrder,
    supportedArtworkSources: Object.freeze(["philenator-local"]),
    supportedMintStatuses: Object.freeze(["not-minted"])
  });
  if (typeof module !== "undefined" && module.exports) module.exports = root.PhilPreviewProvider;
}(globalThis));
