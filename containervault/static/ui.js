"use strict";
(function initDashboard() {
  const tree = document.getElementById("tree");
  const detail = document.getElementById("detailPanel");
  if (!tree || !detail) {
    return;
  }

  const treeEl = tree;
  const detailEl = detail;

  const bootstrapEl = document.getElementById("cv-bootstrap");
  const bootstrap = bootstrapEl && bootstrapEl.textContent
    ? JSON.parse(bootstrapEl.textContent)
    : { namespaces: [] };
  const namespaces = Array.isArray(bootstrap.namespaces) ? bootstrap.namespaces : [];

  const state = {
    expandedNamespace: null,
    expandedRepo: null,
    expandedFolders: {},
    reposByNamespace: {},
    repoLoading: {},
    tagsByRepo: {},
    layersByTag: {},
    layersLoading: {},
    layersVisible: {},
  };

  function escapeHTML(value) {
    return String(value).replace(/[&<>"']/g, (ch) => {
      const map = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      };
      return map[ch] || ch;
    });
  }

  function renderTree() {
    if (!namespaces || namespaces.length === 0) {
      treeEl.innerHTML = '<div class="mono">No namespaces assigned.</div>';
      return;
    }
    treeEl.innerHTML = namespaces
      .map((ns) => {
        const expanded = state.expandedNamespace === ns;
        const caret = expanded ? "&#9662;" : "&#9656;";
        const repos = state.reposByNamespace[ns] || [];
        const repoLoading = state.repoLoading[ns];
        const repoMarkup = expanded
          ? '<div class="branch">' + renderRepos(ns, repos, repoLoading) + "</div>"
          : "";
        return (
          '<button class="node' +
          (expanded ? " active" : "") +
          '" data-type="namespace" data-name="' +
          escapeHTML(ns) +
          '">' +
          '<span class="caret">' +
          caret +
          "</span>" +
          "<span>" +
          escapeHTML(ns) +
          "</span>" +
          "</button>" +
          repoMarkup
        );
      })
      .join("");
  }

  function renderRepos(namespace, repos, loading) {
    if (loading) {
      return '<div class="leaf mono">Loading repositories...</div>';
    }
    if (!repos || repos.length === 0) {
      return '<div class="leaf mono">No repositories found.</div>';
    }
    const tree = buildRepoTree(namespace, repos);
    return renderFolderNode(namespace, tree);
  }

  function repoLabel(namespace, repo) {
    return repo.startsWith(namespace + "/") ? repo.slice(namespace.length + 1) : repo;
  }

  function repoLeafLabel(namespace, repo) {
    const label = repoLabel(namespace, repo);
    const parts = label.split("/");
    return parts[parts.length - 1];
  }

  function buildRepoTree(namespace, repos) {
    const root = { path: "", children: {}, repos: [] };
    repos.forEach((repo) => {
      const label = repoLabel(namespace, repo);
      const parts = label.split("/");
      if (parts.length === 1) {
        root.repos.push(repo);
        return;
      }
      let current = root;
      for (let i = 0; i < parts.length - 1; i += 1) {
        const seg = parts[i];
        if (!current.children[seg]) {
          const path = current.path ? current.path + "/" + seg : seg;
          current.children[seg] = { path, children: {}, repos: [] };
        }
        current = current.children[seg];
      }
      current.repos.push(repo);
    });
    return root;
  }

  function renderFolderNode(namespace, node) {
    const repoMarkup = node.repos
      .slice()
      .sort()
      .map((repo) => renderRepoNode(namespace, repo, repoLeafLabel(namespace, repo)))
      .join("");
    const folderMarkup = Object.keys(node.children)
      .sort()
      .map((folder) => {
        const child = node.children[folder];
        const folderKey = namespace + "/" + child.path;
        const expanded = !!state.expandedFolders[folderKey];
        const caret = expanded ? "&#9662;" : "&#9656;";
        const children = expanded
          ? '<div class="branch">' + renderFolderNode(namespace, child) + "</div>"
          : "";
        return (
          '<button class="node" data-type="folder" data-depth="' +
          escapeHTML(String(child.path.split("/").length)) +
          '" data-namespace="' +
          escapeHTML(namespace) +
          '" data-folder-path="' +
          escapeHTML(child.path) +
          '">' +
          '<span class="caret">' +
          caret +
          "</span>" +
          "<span>" +
          escapeHTML(folder) +
          "</span>" +
          "</button>" +
          children
        );
      })
      .join("");
    return repoMarkup + folderMarkup;
  }

  function renderRepoNode(namespace, repo, label) {
    const expanded = state.expandedRepo === repo;
    const caret = expanded ? "&#9662;" : "&#9656;";
    return (
      '<button class="node' +
      (expanded ? " active" : "") +
      '" data-type="repo" data-depth="' +
      escapeHTML(String(repoLabel(namespace, repo).split("/").length)) +
      '" data-name="' +
      escapeHTML(repo) +
      '">' +
      '<span class="caret">' +
      caret +
      "</span>" +
      "<span>" +
      escapeHTML(label) +
      "</span>" +
      "</button>"
    );
  }

  async function loadRepos(namespace) {
    state.repoLoading[namespace] = true;
    renderTree();
    try {
      const res = await fetch("/api/repos?namespace=" + encodeURIComponent(namespace));
      const text = await res.text();
      if (!res.ok) {
        state.reposByNamespace[namespace] = [];
        state.repoLoading[namespace] = false;
        detailEl.innerHTML = '<div class="mono">' + escapeHTML(text) + "</div>";
        renderTree();
        return;
      }
      const data = JSON.parse(text);
      state.reposByNamespace[namespace] = data.repositories || [];
    } catch (err) {
      detailEl.innerHTML = '<div class="mono">Unable to load repositories.</div>';
    } finally {
      state.repoLoading[namespace] = false;
      renderTree();
    }
  }

  async function loadTags(repo) {
    detailEl.innerHTML = '<div class="mono">Loading tags...</div>';
    try {
      const res = await fetch("/api/tags?repo=" + encodeURIComponent(repo));
      const text = await res.text();
      if (!res.ok) {
        state.tagsByRepo[repo] = [];
        detailEl.innerHTML = '<div class="mono">' + escapeHTML(text) + "</div>";
        return;
      }
      const data = JSON.parse(text);
      state.tagsByRepo[repo] = data.tags || [];
      renderDetail(repo, state.tagsByRepo[repo]);
    } catch (err) {
      detailEl.innerHTML = '<div class="mono">Unable to load tags.</div>';
    }
  }

  function renderDetail(repo, tags) {
    if (!repo) {
      detailEl.innerHTML = "Select a repository to view tags.";
      return;
    }
    const base = window.location.host;
    const rows = (tags || [])
      .map((tag) => {
        return (
          '<div class="tagrow" data-tag-row="' +
          escapeHTML(tag) +
          '" data-tag="' +
          escapeHTML(tag) +
          '" data-repo="' +
          escapeHTML(repo) +
          '">' +
          '<div class="tagrow-header">' +
          '<span class="tagname">' +
          escapeHTML(tag) +
          "</span>" +
          '<span class="stat">loading...</span>' +
          "</div>" +
          '<div class="ref">' +
          escapeHTML(base + "/" + repo + ":" + tag) +
          "</div>" +
          '<div data-layer-container="' +
          escapeHTML(repo + ":" + tag) +
          '"></div>' +
          "</div>"
        );
      })
      .join("");
    detailEl.innerHTML =
      "<div><strong>" +
      escapeHTML(repo) +
      "</strong></div>" +
      '<div class="taglist">' +
      (rows || '<div class="mono">No tags available.</div>') +
      "</div>";
    (tags || []).forEach((tag) => {
      loadTagInfo(repo, tag);
    });
  }

  function formatBytes(value) {
    if (value == null || value < 0) {
      return "unknown size";
    }
    const units = ["B", "KB", "MB", "GB", "TB"];
    let size = value;
    let unitIndex = 0;
    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex += 1;
    }
    return size.toFixed(size >= 10 || unitIndex === 0 ? 0 : 1) + " " + units[unitIndex];
  }

  async function loadTagInfo(repo, tag) {
    try {
      const res = await fetch(
        "/api/taginfo?repo=" + encodeURIComponent(repo) + "&tag=" + encodeURIComponent(tag),
      );
      const text = await res.text();
      if (!res.ok) {
        updateTagRow(tag, { tag, digest: "unavailable", compressed_size: -1 });
        return;
      }
      const data = JSON.parse(text);
      updateTagRow(tag, data);
    } catch (err) {
      updateTagRow(tag, { tag, digest: "unavailable", compressed_size: -1 });
    }
  }

  function updateTagRow(tag, data) {
    const row = detailEl.querySelector('[data-tag-row="' + CSS.escape(tag) + '"]');
    if (!row) {
      return;
    }
    const digest = data.digest ? data.digest : "unknown digest";
    const compressed = formatBytes(data.compressed_size);
    const header = row.querySelector(".tagrow-header");
    if (!header) {
      return;
    }
    header.innerHTML =
      '<span class="tagname">' +
      escapeHTML(tag) +
      "</span>" +
      '<span class="tagstats">' +
      '<span class="stat">compressed ' +
      escapeHTML(compressed) +
      "</span>" +
      '<span class="stat mono">' +
      escapeHTML(digest) +
      "</span>" +
      "</span>";
  }

  function renderLayers(tagKey) {
    if (state.layersLoading[tagKey]) {
      return '<div class="layers"><div class="mono">Loading layers...</div></div>';
    }
    const layers = state.layersByTag[tagKey] || [];
    if (layers.length === 0) {
      return '<div class="layers"><div class="mono">No layers found.</div></div>';
    }
    return (
      '<div class="layers">' +
      layers
        .map((layer) => {
          return (
            '<div class="layer">' +
            '<code>' +
            escapeHTML(layer.digest) +
            "</code>" +
            "<span>" +
            escapeHTML(formatBytes(layer.size)) +
            "</span>" +
            "</div>"
          );
        })
        .join("") +
      "</div>"
    );
  }

  async function loadLayers(repo, tag) {
    const key = repo + ":" + tag;
    if (state.layersByTag[key]) {
      return;
    }
    state.layersLoading[key] = true;
    updateLayersUI(key);
    try {
      const res = await fetch(
        "/api/taglayers?repo=" + encodeURIComponent(repo) + "&tag=" + encodeURIComponent(tag),
      );
      const text = await res.text();
      if (!res.ok) {
        state.layersByTag[key] = [];
        state.layersLoading[key] = false;
        updateLayersUI(key);
        return;
      }
      const data = JSON.parse(text);
      state.layersByTag[key] = data.layers || [];
    } catch (err) {
      state.layersByTag[key] = [];
    } finally {
      state.layersLoading[key] = false;
      updateLayersUI(key);
    }
  }

  function updateLayersUI(tagKey) {
    const container = detailEl.querySelector('[data-layer-container="' + CSS.escape(tagKey) + '"]');
    if (!container) {
      return;
    }
    if (!state.layersVisible[tagKey]) {
      container.innerHTML = "";
      return;
    }
    container.innerHTML = renderLayers(tagKey);
  }

  treeEl.addEventListener("click", (event) => {
    const target = event.target;
    const button = target && target.closest ? target.closest("button.node") : null;
    if (!button) {
      return;
    }
    const type = button.getAttribute("data-type");
    if (type === "folder") {
      const folder = button.getAttribute("data-folder-path");
      const namespace = button.getAttribute("data-namespace");
      if (!folder || !namespace) {
        return;
      }
      const key = namespace + "/" + folder;
      state.expandedFolders[key] = !state.expandedFolders[key];
      renderTree();
      return;
    }
    const name = button.getAttribute("data-name");
    if (!name) {
      return;
    }
    if (type === "namespace") {
      if (state.expandedNamespace === name) {
        state.expandedNamespace = null;
        state.expandedRepo = null;
        renderTree();
        return;
      }
      state.expandedNamespace = name;
      state.expandedRepo = null;
      if (!state.reposByNamespace[name]) {
        loadRepos(name);
      } else {
        renderTree();
      }
      return;
    }
    if (type === "repo") {
      if (state.expandedRepo === name) {
        state.expandedRepo = null;
        renderTree();
        return;
      }
      state.expandedRepo = name;
      renderTree();
      if (!state.tagsByRepo[name]) {
        loadTags(name);
      } else {
        renderDetail(name, state.tagsByRepo[name]);
      }
    }
  });

  detailEl.addEventListener("click", (event) => {
    const target = event.target;
    const row = target && target.closest ? target.closest(".tagrow") : null;
    if (!row) {
      return;
    }
    const tag = row.getAttribute("data-tag");
    const repo = row.getAttribute("data-repo");
    if (!tag || !repo) {
      return;
    }
    const key = repo + ":" + tag;
    state.layersVisible[key] = !state.layersVisible[key];
    const container = row.querySelector('[data-layer-container="' + CSS.escape(key) + '"]');
    if (container) {
      if (state.layersVisible[key]) {
        container.innerHTML = renderLayers(key);
      } else {
        container.innerHTML = "";
      }
    }
    if (state.layersVisible[key]) {
      loadLayers(repo, tag);
    }
  });

  renderTree();
})();
