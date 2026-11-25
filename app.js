const accessForm = document.querySelector("#access-form");
const statusMessage = document.querySelector("#status");
const loginScreen = document.querySelector("#login-screen");
const appShell = document.querySelector("#app-shell");
const userIdInput = document.querySelector("#user-id");
const userNameInput = document.querySelector("#user-name");
const accessKeyInput = document.querySelector("#access-key");
const historyStorageKey = "directorio-historial-accesos";
const lockoutStorageKey = "directorio-bloqueo-acceso";
const firewallHistoryStorageKey = "directorio-historial-firewall";
const maxFailedAttempts = 3;
const lockoutDurationMs = 3 * 60 * 1000;
const memoryStorage = new Map();
const fileDatabaseName = "baultsafe-files";
const fileStoreName = "files";

const filePicker = document.querySelector("#file-picker");
const fileList = document.querySelector("#file-list");
const fileSearch = document.querySelector("#file-search");
const sortFiles = document.querySelector("#sort-files");
const firewallToggle = document.querySelector("#firewall-toggle");
const runFileScanButton = document.querySelector("#run-file-scan");

let availableUsers = [];
let accessHistory = [];
let firewallHistory = [];
let failedAttempts = 0;
let lockedUntil = 0;
let lockoutInterval;
let firewallStartedAt = 0;
let firewallInterval;
let files = [];
let fileDatabase;
let fileStorageError;
let currentUser;
let persistentStorageAvailable = true;
let scanRound = 0;
let pendingFiles = [];
let previewUrl = null;
const sampleScanResults = [
  { label: "Sin alertas", kind: "status-on" },
  { label: "Revisar", kind: "status-neutral" },
  { label: "Riesgo alto", kind: "status-off" },
];

function isValidUser(userRecord) {
  return (
    userRecord !== null &&
    typeof userRecord === "object" &&
    typeof userRecord.nombre === "string" &&
    typeof userRecord.id === "string" &&
    /^\d{4}$/.test(userRecord.id) &&
    typeof userRecord.clave_acceso === "string" &&
    /^\d{5}$/.test(userRecord.clave_acceso)
  );
}

function readStorage(storageKey, fallbackValue) {
  let storedValue;
  if (persistentStorageAvailable) {
    try {
      storedValue = localStorage.getItem(storageKey);
    } catch (error) {
      if (!(error instanceof DOMException) || error.name !== "SecurityError") {
        throw error;
      }
      persistentStorageAvailable = false;
      console.warn("El navegador bloqueó localStorage; los datos durarán solo esta sesión.", error);
    }
  }
  if (!persistentStorageAvailable) {
    storedValue = memoryStorage.get(storageKey) ?? null;
  }
  return storedValue === null ? fallbackValue : JSON.parse(storedValue);
}

function writeStorage(storageKey, storageData) {
  const serializedValue = JSON.stringify(storageData);
  if (persistentStorageAvailable) {
    try {
      localStorage.setItem(storageKey, serializedValue);
    } catch (error) {
      if (!(error instanceof DOMException) || error.name !== "SecurityError") {
        throw error;
      }
      persistentStorageAvailable = false;
      console.warn("El navegador bloqueó localStorage; los datos durarán solo esta sesión.", error);
    }
  }
  memoryStorage.set(storageKey, serializedValue);
}

function openFileDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(fileDatabaseName, 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(fileStoreName, { keyPath: "id" });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error("No se pudo abrir el almacenamiento de archivos."));
    request.onblocked = () => reject(new Error("El almacenamiento de archivos está bloqueado por otra pestaña."));
  });
}

function readSavedFiles() {
  return new Promise((resolve, reject) => {
    const transaction = fileDatabase.transaction(fileStoreName, "readonly");
    const request = transaction.objectStore(fileStoreName).getAll();
    let savedFiles;
    request.onsuccess = () => {
      savedFiles = request.result;
    };
    transaction.oncomplete = () => resolve(savedFiles);
    request.onerror = () => reject(request.error || new Error("No se pudieron cargar los archivos guardados."));
    transaction.onabort = () => reject(transaction.error || new Error("No se pudieron cargar los archivos guardados."));
  });
}

function saveFiles(savedFiles) {
  return new Promise((resolve, reject) => {
    if (!fileDatabase || fileStorageError) {
      reject(fileStorageError || new Error("El almacenamiento persistente de archivos no está disponible."));
      return;
    }

    const transaction = fileDatabase.transaction(fileStoreName, "readwrite");
    const store = transaction.objectStore(fileStoreName);
    store.clear();
    for (const file of savedFiles) {
      const { scanResult, ...savedFile } = file;
      store.put(savedFile);
    }
    transaction.oncomplete = resolve;
    transaction.onerror = () => reject(transaction.error || new Error("No se pudieron guardar los archivos."));
    transaction.onabort = () => reject(transaction.error || new Error("No se pudieron guardar los archivos."));
  });
}

function saveLockoutState() {
  writeStorage(lockoutStorageKey, { failedAttempts, lockedUntil });
}

function loadLockoutState() {
  const savedState = readStorage(lockoutStorageKey, { failedAttempts: 0, lockedUntil: 0 });
  if (
    savedState === null ||
    typeof savedState !== "object" ||
    !Number.isInteger(savedState.failedAttempts) ||
    savedState.failedAttempts < 0 ||
    savedState.failedAttempts > maxFailedAttempts ||
    !Number.isFinite(savedState.lockedUntil)
  ) {
    throw new Error("El estado de bloqueo guardado no es válido.");
  }

  failedAttempts = savedState.failedAttempts;
  lockedUntil = savedState.lockedUntil;
  if (lockedUntil > 0 && lockedUntil <= Date.now()) {
    failedAttempts = 0;
    lockedUntil = 0;
    saveLockoutState();
  } else if (lockedUntil > Date.now() && failedAttempts < maxFailedAttempts) {
    throw new Error("El estado de bloqueo guardado no es válido.");
  }
}

function showStatus(message, kind = "") {
  statusMessage.textContent = message;
  statusMessage.className = `status${kind ? ` status-${kind}` : ""}`;
}

function setLoginDisabled(disabled) {
  for (const control of accessForm.querySelectorAll("input, button")) {
    control.disabled = disabled;
  }
}

function updateLockoutStatus() {
  const remainingMs = lockedUntil - Date.now();
  if (remainingMs <= 0) {
    clearInterval(lockoutInterval);
    lockoutInterval = undefined;
    failedAttempts = 0;
    lockedUntil = 0;
    saveLockoutState();
    setLoginDisabled(false);
    showStatus("El bloqueo terminó. Ya puedes intentar ingresar nuevamente.");
    userIdInput.focus();
    return;
  }

  const remainingSeconds = Math.ceil(remainingMs / 1000);
  const minutes = Math.floor(remainingSeconds / 60);
  const seconds = String(remainingSeconds % 60).padStart(2, "0");
  setLoginDisabled(true);
  showStatus(
    `Se agotaron los intentos. Espera 3 minutos antes de volver a acceder. Tiempo restante: ${minutes}:${seconds}.`,
    "lockout",
  );
}

function beginLockout() {
  lockedUntil = Date.now() + lockoutDurationMs;
  saveLockoutState();
  updateLockoutStatus();
  lockoutInterval = setInterval(updateLockoutStatus, 1000);
}

function loadAccessHistory(initialHistory) {
  const savedHistory = readStorage(historyStorageKey, initialHistory);
  if (
    !Array.isArray(savedHistory) ||
    !savedHistory.every(
      (entry) =>
        entry !== null &&
        typeof entry === "object" &&
        typeof entry.userId === "string" &&
        typeof entry.name === "string" &&
        typeof entry.timestamp === "string" &&
        !Number.isNaN(Date.parse(entry.timestamp)),
    )
  ) {
    throw new Error("El historial de accesos guardado no es válido.");
  }
  accessHistory = savedHistory;
}

function renderAccessHistory() {
  const container = document.querySelector("#access-history");
  if (accessHistory.length === 0) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "Todavía no hay accesos registrados.";
    container.replaceChildren(empty);
    return;
  }

  const historyList = document.createElement("ol");
  historyList.className = "history-list";
  for (const entry of [...accessHistory].reverse()) {
    const item = document.createElement("li");
    const timestamp = new Date(entry.timestamp);
    const date = document.createElement("span");
    date.className = "history-date";
    date.textContent = timestamp.toLocaleString("es", {
      dateStyle: "medium",
      timeStyle: "short",
    });
    const userName = document.createElement("strong");
    userName.textContent = entry.name;
    const id = document.createElement("span");
    id.className = "history-id";
    id.textContent = `ID ${entry.userId}`;
    item.append(userName, id, date);
    historyList.append(item);
  }
  container.replaceChildren(historyList);
}

function loadFirewallHistory() {
  const savedHistory = readStorage(firewallHistoryStorageKey, []);
  if (
    !Array.isArray(savedHistory) ||
    !savedHistory.every(
      (entry) =>
        entry !== null &&
        typeof entry === "object" &&
        (entry.result === "success" || entry.result === "failure") &&
        typeof entry.timestamp === "string" &&
        !Number.isNaN(Date.parse(entry.timestamp)),
    )
  ) {
    throw new Error("El historial del firewall guardado no es válido.");
  }
  firewallHistory = savedHistory.slice(-100);
}

function renderFirewallHistory() {
  const container = document.querySelector("#firewall-history-list");
  const summary = document.querySelector("#firewall-history-summary");
  summary.textContent = `${firewallHistory.length} ${firewallHistory.length === 1 ? "registro" : "registros"}`;

  if (firewallHistory.length === 0) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "Todavía no hay resultados registrados.";
    container.replaceChildren(empty);
    return;
  }

  const list = document.createElement("ol");
  list.className = "firewall-event-list";
  for (const entry of [...firewallHistory].reverse()) {
    const item = document.createElement("li");
    const result = document.createElement("strong");
    result.textContent = entry.result === "success" ? "Defensa exitosa" : "Defensa fallida";
    const timestamp = document.createElement("time");
    timestamp.dateTime = entry.timestamp;
    timestamp.textContent = new Date(entry.timestamp).toLocaleString("es", {
      dateStyle: "medium",
      timeStyle: "short",
    });
    const outcome = document.createElement("span");
    outcome.className = `status-pill ${entry.result === "success" ? "status-on" : "status-off"}`;
    const indicator = document.createElement("span");
    outcome.append(indicator, document.createTextNode(entry.result === "success" ? " Éxito" : " Fallo"));
    item.append(result, timestamp, outcome);
    list.append(item);
  }
  container.replaceChildren(list);
}

function recordFirewallOutcome(result) {
  const updatedHistory = [
    ...firewallHistory,
    { result, timestamp: new Date().toISOString() },
  ].slice(-100);
  writeStorage(firewallHistoryStorageKey, updatedHistory);
  firewallHistory = updatedHistory;
  renderFirewallHistory();
}

function recordAccess(authenticatedUser) {
  accessHistory.push({
    userId: authenticatedUser.id,
    name: authenticatedUser.nombre,
    timestamp: new Date().toISOString(),
  });
  accessHistory = accessHistory.slice(-100);
  writeStorage(historyStorageKey, accessHistory);
  renderAccessHistory();
}

function enterApp(authenticatedUser) {
  currentUser = authenticatedUser;
  document.querySelector("#profile-name").textContent = authenticatedUser.nombre;
  document.querySelector("#profile-avatar").textContent = authenticatedUser.nombre.trim().charAt(0).toLocaleUpperCase("es");
  loginScreen.hidden = true;
  appShell.hidden = false;
  showView("files-view");
}

function handleLogin(event) {
  event.preventDefault();
  if (lockedUntil > Date.now()) {
    updateLockoutStatus();
    return;
  }

  const enteredId = userIdInput.value.trim();
  const enteredName = userNameInput.value.trim().toLocaleLowerCase("es");
  const matchedUser = availableUsers.find(
    (candidate) =>
      candidate.id === enteredId &&
      candidate.nombre.trim().toLocaleLowerCase("es") === enteredName &&
      candidate.clave_acceso === accessKeyInput.value,
  );

  if (!matchedUser) {
    failedAttempts += 1;
    accessKeyInput.value = "";
    if (failedAttempts >= maxFailedAttempts) {
      beginLockout();
      return;
    }

    saveLockoutState();
    const remaining = maxFailedAttempts - failedAttempts;
    showStatus(`Datos incorrectos. Te quedan ${remaining} ${remaining === 1 ? "intento" : "intentos"}.`, "error");
    accessKeyInput.focus();
    return;
  }

  failedAttempts = 0;
  lockedUntil = 0;
  saveLockoutState();
  try {
    recordAccess(matchedUser);
  } catch (error) {
    console.error("No se pudo guardar el acceso:", error);
    showStatus("No se pudo guardar el historial. Revisa el almacenamiento de este navegador.", "error");
    return;
  }
  accessForm.reset();
  enterApp(matchedUser);
}

function showView(viewId) {
  for (const view of document.querySelectorAll(".view")) {
    view.hidden = view.id !== viewId;
  }
  for (const button of document.querySelectorAll(".nav-item")) {
    const selected = button.dataset.view === viewId;
    button.classList.toggle("is-active", selected);
    if (selected) {
      button.setAttribute("aria-current", "page");
    } else {
      button.removeAttribute("aria-current");
    }
  }

  const titles = {
    "files-view": "Mis archivos",
    "security-view": "Seguridad",
    "history-view": "Registros de acceso",
  };
  document.querySelector("#current-section").textContent = titles[viewId];
}

function formatBytes(byteCount) {
  if (byteCount < 1024) return `${byteCount} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let scaledSize = byteCount / 1024;
  let unitIndex = 0;
  while (scaledSize >= 1024 && unitIndex < units.length - 1) {
    scaledSize /= 1024;
    unitIndex += 1;
  }
  return `${scaledSize.toFixed(scaledSize < 10 ? 1 : 0)} ${units[unitIndex]}`;
}

function getFileExtension(fileName) {
  const extension = fileName.split(".").pop();
  return extension && extension !== fileName ? extension.slice(0, 4).toUpperCase() : "FILE";
}

function compareFiles(firstFile, secondFile) {
  const nameComparison = firstFile.name.localeCompare(secondFile.name, "es", {
    numeric: true,
    sensitivity: "base",
  });
  if (sortFiles.value === "za") return -nameComparison;
  if (sortFiles.value === "number-asc" || sortFiles.value === "number-desc") {
    const firstNumberMatch = firstFile.name.match(/\d+/);
    const secondNumberMatch = secondFile.name.match(/\d+/);
    const firstFileNumber = firstNumberMatch ? Number(firstNumberMatch[0]) : Number.POSITIVE_INFINITY;
    const secondFileNumber = secondNumberMatch ? Number(secondNumberMatch[0]) : Number.POSITIVE_INFINITY;
    const numberComparison = firstFileNumber - secondFileNumber || nameComparison;
    return sortFiles.value === "number-desc" ? -numberComparison : numberComparison;
  }
  return nameComparison;
}

function createFileRow(file) {
  const row = document.createElement("article");
  row.className = "file-row";
  row.classList.toggle("has-scan-result", Boolean(file.scanResult));

  const fileIdentity = document.createElement("div");
  fileIdentity.className = "file-identity";
  const fileIcon = document.createElement("span");
  fileIcon.className = `file-type-icon file-type-${getFileExtension(file.name).toLowerCase()}`;
  fileIcon.textContent = getFileExtension(file.name);
  const fileDetails = document.createElement("span");
  fileDetails.className = "file-details";
  const fileName = document.createElement("strong");
  fileName.className = "file-name";
  fileName.textContent = file.name;
  const fileDate = document.createElement("small");
  fileDate.textContent = `Añadido ${new Date(file.addedAt).toLocaleDateString("es")}`;
  fileDetails.append(fileName, fileDate);
  fileIdentity.append(fileIcon, fileDetails);

  const size = document.createElement("span");
  size.className = "file-size";
  size.textContent = formatBytes(file.size);

  const classification = document.createElement("span");
  classification.className = "file-classification";
  classification.textContent = file.classification || "Sin clasificar";

  const importance = document.createElement("select");
  importance.className = `importance-select importance-${file.importance}`;
  importance.setAttribute("aria-label", `Relevancia de ${file.name}`);
  for (const [importanceLevel, importanceLabel] of [
    ["low", "No importante"],
    ["normal", "Normal"],
    ["high", "Relevante"],
  ]) {
    const option = document.createElement("option");
    option.value = importanceLevel;
    option.textContent = importanceLabel;
    option.selected = file.importance === importanceLevel;
    importance.append(option);
  }
  importance.addEventListener("change", () => {
    const previousImportance = file.importance;
    file.importance = importance.value;
    importance.className = `importance-select importance-${file.importance}`;
    saveFiles(files).catch((error) => {
      file.importance = previousImportance;
      importance.value = previousImportance;
      importance.className = `importance-select importance-${previousImportance}`;
      console.error("No se pudo guardar la relevancia del archivo:", error);
      showStatus("No se pudo guardar el cambio. Comprueba el espacio disponible en el navegador.", "error");
    });
  });

  const preview = document.createElement("button");
  preview.className = "preview-file";
  preview.type = "button";
  preview.innerHTML = '<span aria-hidden="true">◉</span><span>Revisar</span>';
  preview.setAttribute("aria-label", `Revisar ${file.name}`);
  preview.addEventListener("click", () => openFilePreview(file));

  const remove = document.createElement("button");
  remove.className = "icon-button remove-file";
  remove.type = "button";
  remove.setAttribute("aria-label", `Quitar ${file.name} de la lista`);
  remove.title = "Quitar de la lista";
  remove.textContent = "×";
  remove.addEventListener("click", async () => {
    const updatedFiles = files.filter((item) => item.id !== file.id);
    try {
      await saveFiles(updatedFiles);
      files = updatedFiles;
      renderFiles();
    } catch (error) {
      console.error("No se pudo quitar el archivo guardado:", error);
      showStatus("No se pudo quitar el archivo. Comprueba el almacenamiento del navegador.", "error");
    }
  });

  if (file.scanResult) {
    const scanResult = document.createElement("span");
    scanResult.className = `file-scan-badge ${file.scanResult.kind}`;
    scanResult.textContent = file.scanResult.label;
    scanResult.title = "Estado de ejemplo; el contenido del archivo no fue analizado";
    row.classList.add("showing-result");
    row.append(fileIdentity, size, classification, importance, preview, remove, scanResult);
  } else {
    row.append(fileIdentity, size, classification, importance, preview, remove);
  }
  return row;
}

function renderFiles() {
  const query = fileSearch.value.trim().toLocaleLowerCase("es");
  const filteredFiles = files
    .filter((file) => file.name.toLocaleLowerCase("es").includes(query))
    .sort(compareFiles);
  const totalSize = files.reduce((total, file) => total + file.size, 0);

  document.querySelector("#file-count").textContent = String(files.length);
  document.querySelector("#file-total-size").textContent = formatBytes(totalSize);
  document.querySelector("#security-file-count").textContent = String(files.length);
  updateFileScanSummary();
  document.querySelector("#file-summary").textContent =
    files.length === 0
      ? "Tus archivos añadidos aparecerán aquí."
      : `${files.length} ${files.length === 1 ? "archivo guardado" : "archivos guardados"} en este dispositivo`;
  document.querySelector(".session-footnote").lastChild.textContent = fileStorageError
    ? " No está disponible el almacenamiento persistente del navegador; no se pueden guardar archivos."
    : " Los archivos y su contenido se guardan en este navegador y no se suben a ningún servidor.";

  if (filteredFiles.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-files";
    const icon = document.createElement("span");
    icon.className = "empty-files-icon";
    icon.textContent = query ? "⌕" : "▤";
    const heading = document.createElement("strong");
    heading.textContent = query ? "No encontramos archivos" : "Tu espacio está listo";
    const message = document.createElement("p");
    message.textContent = query
      ? "Prueba con otro término de búsqueda."
      : "Añade archivos para guardarlos en este dispositivo y volver a encontrarlos al regresar.";
    empty.append(icon, heading, message);
    fileList.replaceChildren(empty);
    return;
  }

  const fragment = document.createDocumentFragment();
  for (const file of filteredFiles) {
    fragment.append(createFileRow(file));
  }
  fileList.replaceChildren(fragment);
}

function openFileAddDialog(selectedFiles) {
  const uniqueFiles = Array.from(selectedFiles).filter((selectedFile) =>
    !files.some((file) => file.name === selectedFile.name && file.size === selectedFile.size),
  );

  if (uniqueFiles.length === 0) {
    showStatus("Los archivos seleccionados ya están en el gestor.", "neutral");
    return;
  }

  pendingFiles = uniqueFiles;
  const list = document.querySelector("#file-add-list");
  const fragment = document.createDocumentFragment();

  for (const [index, selectedFile] of uniqueFiles.entries()) {
    const item = document.createElement("article");
    item.className = "file-add-item";

    const icon = document.createElement("span");
    icon.className = `file-type-icon file-type-${getFileExtension(selectedFile.name).toLowerCase()}`;
    icon.textContent = getFileExtension(selectedFile.name);

    const details = document.createElement("div");
    details.className = "file-add-details";
    const name = document.createElement("strong");
    name.textContent = selectedFile.name;
    const size = document.createElement("small");
    size.textContent = formatBytes(selectedFile.size);
    details.append(name, size);

    const fields = document.createElement("div");
    fields.className = "file-add-fields";
    const classificationLabel = document.createElement("label");
    classificationLabel.textContent = "Clasificación";
    const classificationInput = document.createElement("input");
    classificationInput.type = "text";
    classificationInput.value = "Personal";
    classificationInput.setAttribute("list", "file-classifications");
    classificationInput.dataset.pendingIndex = String(index);
    classificationInput.setAttribute("aria-label", `Clasificación de ${selectedFile.name}`);
    classificationLabel.append(classificationInput);

    const importanceLabel = document.createElement("label");
    importanceLabel.textContent = "Relevancia";
    const importanceSelect = document.createElement("select");
    importanceSelect.dataset.pendingIndex = String(index);
    for (const [value, label] of [["low", "No importante"], ["normal", "Normal"], ["high", "Relevante"]]) {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = label;
      option.selected = value === "normal";
      importanceSelect.append(option);
    }
    importanceLabel.append(importanceSelect);
    fields.append(classificationLabel, importanceLabel);

    item.append(icon, details, fields);
    fragment.append(item);
  }

  list.replaceChildren(fragment);
  const dialog = document.querySelector("#file-add-dialog");
  if (typeof dialog.showModal === "function") dialog.showModal();
  else dialog.setAttribute("open", "");
}

async function addSelectedFiles(selectedFiles) {
  let addedFile = false;
  const updatedFiles = files.map((file) => ({ ...file, scanResult: null }));
  for (const selectedFile of selectedFiles) {
    const duplicate = updatedFiles.some(
      (file) => file.name === selectedFile.name && file.size === selectedFile.size,
    );
    if (duplicate) continue;

    updatedFiles.push({
      id: `${Date.now()}-${Math.random()}`,
      name: selectedFile.name,
      size: selectedFile.size,
      type: selectedFile.type,
      sourceFile: selectedFile,
      classification: selectedFile.classification || "Personal",
      addedAt: new Date().toISOString(),
      importance: selectedFile.importance || "normal",
      scanResult: null,
    });
    addedFile = true;
  }
  if (addedFile) {
    await saveFiles(updatedFiles);
    files = updatedFiles;
  }
  renderFiles();
  return addedFile;
}

async function openFilePreview(file) {
  const dialog = document.querySelector("#file-preview-dialog");
  const title = document.querySelector("#file-preview-title");
  const icon = document.querySelector("#file-preview-icon");
  const meta = document.querySelector("#file-preview-meta");
  const content = document.querySelector("#file-preview-content");
  const download = document.querySelector("#file-preview-download");

  title.textContent = file.name;
  icon.textContent = getFileExtension(file.name);
  icon.className = `file-preview-icon file-type-${getFileExtension(file.name).toLowerCase()}`;
  meta.textContent = `${formatBytes(file.size)} · ${file.classification || "Sin clasificar"} · Añadido ${new Date(file.addedAt).toLocaleDateString("es")}`;
  content.replaceChildren();

  if (previewUrl) URL.revokeObjectURL(previewUrl);
  previewUrl = file.sourceFile ? URL.createObjectURL(file.sourceFile) : null;

  download.onclick = () => {
    if (!previewUrl) return;
    const link = document.createElement("a");
    link.href = previewUrl;
    link.download = file.name;
    link.click();
  };

  if (!file.sourceFile) {
    content.innerHTML = '<div class="preview-unavailable"><strong>Vista previa no disponible</strong><p>No se encontraron los datos guardados de este archivo.</p></div>';
  } else if (file.type.startsWith("image/")) {
    const image = document.createElement("img");
    image.src = previewUrl;
    image.alt = `Vista previa de ${file.name}`;
    content.append(image);
  } else if (file.type === "application/pdf") {
    const pdf = document.createElement("iframe");
    pdf.src = previewUrl;
    pdf.title = `Vista previa de ${file.name}`;
    content.append(pdf);
  } else if (file.type.startsWith("text/") || /\.(txt|csv|json|js|css|html|md|xml)$/i.test(file.name)) {
    try {
      const text = await file.sourceFile.text();
      const pre = document.createElement("pre");
      pre.textContent = text.slice(0, 100000);
      content.append(pre);
    } catch (error) {
      console.error("No se pudo leer el archivo para la vista previa:", error);
      content.innerHTML = '<div class="preview-unavailable"><strong>No se pudo leer el texto</strong></div>';
    }
  } else if (file.type.startsWith("video/")) {
    const video = document.createElement("video");
    video.src = previewUrl;
    video.controls = true;
    content.append(video);
  } else if (file.type.startsWith("audio/")) {
    const audio = document.createElement("audio");
    audio.src = previewUrl;
    audio.controls = true;
    content.append(audio);
  } else {
    content.innerHTML = '<div class="preview-unavailable"><strong>Vista previa limitada</strong><p>Este formato no puede mostrarse en el navegador. Puedes abrirlo o descargarlo.</p></div>';
  }

  if (typeof dialog.showModal === "function") dialog.showModal();
  else dialog.setAttribute("open", "");
}

function updateFileScanSummary() {
  const pill = document.querySelector("#file-scan-pill");
  const title = document.querySelector("#file-scan-title");
  const description = document.querySelector("#file-scan-description");
  const resultsContainer = document.querySelector("#file-scan-results");
  const analyzedFiles = files.filter((file) => file.scanResult);

  if (analyzedFiles.length === 0) {
    pill.className = "status-pill status-neutral";
    pill.lastChild.textContent = " Pendiente";
    title.textContent = "Revisión de archivos";
    description.textContent = files.length === 0
      ? "No hay archivos para mostrar. Añade uno o más archivos y vuelve a intentarlo."
      : "Genera resultados de ejemplo para ver cómo se mostrarían los estados. No se lee el contenido de los archivos.";
    resultsContainer.replaceChildren();
    return;
  }

  const riskCount = analyzedFiles.filter((file) => file.scanResult.kind === "status-off").length;
  const reviewCount = analyzedFiles.filter((file) => file.scanResult.kind === "status-neutral").length;
  const summary = riskCount > 0
    ? `${riskCount} riesgo${riskCount === 1 ? "" : "s"} de ejemplo`
    : reviewCount > 0
      ? `${reviewCount} por revisar`
      : "Sin alertas de ejemplo";
  pill.className = `status-pill ${riskCount > 0 ? "status-off" : reviewCount > 0 ? "status-neutral" : "status-on"}`;
  pill.lastChild.textContent = ` ${summary}`;
  title.textContent = "Resultados de ejemplo";
  description.textContent =
    "Estos estados ilustran la interfaz; no representan un análisis ni una detección real.";

  const scanResultsList = document.createElement("ul");
  scanResultsList.className = "scan-result-list";
  for (const file of analyzedFiles) {
    const item = document.createElement("li");
    const fileNameLabel = document.createElement("span");
    fileNameLabel.textContent = file.name;
    const result = document.createElement("span");
    result.className = `file-scan-badge ${file.scanResult.kind}`;
    result.textContent = file.scanResult.label;
    item.append(fileNameLabel, result);
    scanResultsList.append(item);
  }
  resultsContainer.replaceChildren(scanResultsList);
}

function generateExampleScanResults() {
  if (files.length === 0) {
    document.querySelector("#file-scan-description").textContent =
      "No hay archivos para mostrar. Añade uno o más archivos y vuelve a intentarlo.";
    return;
  }

  for (const [index, file] of files.entries()) {
    const resultIndex = (index + scanRound) % sampleScanResults.length;
    file.scanResult = sampleScanResults[resultIndex];
  }
  scanRound = (scanRound + 1) % sampleScanResults.length;
  updateFileScanSummary();
  renderFiles();
}

function formatElapsedTime(milliseconds) {
  const totalSeconds = Math.floor(milliseconds / 1000);
  const hours = String(Math.floor(totalSeconds / 3600)).padStart(2, "0");
  const minutes = String(Math.floor((totalSeconds % 3600) / 60)).padStart(2, "0");
  const seconds = String(totalSeconds % 60).padStart(2, "0");
  return `${hours}:${minutes}:${seconds}`;
}

function updateFirewallTimer() {
  if (!firewallStartedAt) return;
  document.querySelector("#firewall-timer").textContent = formatElapsedTime(Date.now() - firewallStartedAt);
}

function setFirewallActive(active) {
  const pill = document.querySelector("#firewall-pill");
  const title = document.querySelector("#firewall-title");
  const description = document.querySelector("#firewall-description");
  const label = document.querySelector("#firewall-button-label");
  const symbol = document.querySelector("#firewall-symbol");

  firewallToggle.setAttribute("aria-pressed", String(active));
  firewallToggle.classList.toggle("is-on", active);
  pill.className = `status-pill ${active ? "status-on" : "status-off"}`;
  pill.lastChild.textContent = active ? " Activo" : " Inactivo";
  title.textContent = active ? "Indicador activo" : "Indicador de firewall";
  description.textContent = active
    ? "El indicador del firewall está activo en esta página."
    : "Activa el indicador para ver su estado y tiempo de actividad.";
  label.textContent = active ? "Detener indicador" : "Levantar firewall";
  symbol.textContent = active ? "✓" : "⏻";

  if (active) {
    firewallStartedAt = Date.now();
    updateFirewallTimer();
    firewallInterval = setInterval(updateFirewallTimer, 1000);
  } else {
    clearInterval(firewallInterval);
    firewallInterval = undefined;
    firewallStartedAt = 0;
    document.querySelector("#firewall-timer").textContent = "00:00:00";
  }
}

function bindInterface() {
  document.querySelectorAll(".nav-item").forEach((button) => {
    button.addEventListener("click", () => showView(button.dataset.view));
  });

  document.querySelector("#logout-button").addEventListener("click", () => {
    currentUser = undefined;
    appShell.hidden = true;
    loginScreen.hidden = false;
    accessForm.reset();
    showStatus("Sesión cerrada. Vuelve a ingresar para continuar.");
    setFirewallActive(false);
  });

  document.querySelector("#add-files-button").addEventListener("click", () => filePicker.click());
  filePicker.addEventListener("change", () => {
    openFileAddDialog(Array.from(filePicker.files));
    filePicker.value = "";
  });
  document.querySelector("#file-add-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const classifications = document.querySelectorAll("#file-add-list input[data-pending-index]");
    const importances = document.querySelectorAll("#file-add-list select[data-pending-index]");
    for (const [index, selectedFile] of pendingFiles.entries()) {
      selectedFile.classification = classifications[index].value.trim() || "Personal";
      selectedFile.importance = importances[index].value;
    }
    try {
      await addSelectedFiles(pendingFiles);
      pendingFiles = [];
      document.querySelector("#file-add-dialog").close();
      showStatus("Los archivos se guardaron en este dispositivo.", "neutral");
    } catch (error) {
      console.error("No se pudieron guardar los archivos:", error);
      showStatus("No se pudieron guardar los archivos. Comprueba el espacio y los permisos del navegador.", "error");
    }
  });
  document.querySelector("#file-preview-dialog").addEventListener("close", () => {
    if (previewUrl) {
      URL.revokeObjectURL(previewUrl);
      previewUrl = null;
    }
  });
  document.querySelectorAll("[data-close-dialog]").forEach((button) => {
    button.addEventListener("click", () => {
      const dialog = document.querySelector(`#${button.dataset.closeDialog}`);
      if (typeof dialog.close === "function") dialog.close();
      else dialog.removeAttribute("open");
      if (button.dataset.closeDialog === "file-preview-dialog" && previewUrl) {
        URL.revokeObjectURL(previewUrl);
        previewUrl = null;
      }
    });
  });
  fileSearch.addEventListener("input", renderFiles);
  sortFiles.addEventListener("change", renderFiles);
  firewallToggle.addEventListener("click", () => {
    const active = firewallToggle.getAttribute("aria-pressed") !== "true";
    setFirewallActive(active);
    try {
      recordFirewallOutcome(active ? "success" : "failure");
    } catch (error) {
      console.error("No se pudo registrar el resultado del indicador de firewall:", error);
      showStatus("No se pudo guardar el registro del firewall en este navegador.", "error");
    }
  });
  runFileScanButton.addEventListener("click", generateExampleScanResults);
}

async function initialize() {
  try {
    let directoryData;
    if (location.protocol === "file:") {
      const embeddedData = document.querySelector("#baultsafe-data");
      if (!embeddedData) {
        throw new Error("No se encontraron los datos incluidos en index.html.");
      }
      directoryData = JSON.parse(embeddedData.textContent);
    } else {
      const response = await fetch("./data.json");
      if (!response.ok) {
        throw new Error(`No se pudo cargar data.json (${response.status}).`);
      }
      directoryData = await response.json();
    }
    if (directoryData === null || typeof directoryData !== "object" || Array.isArray(directoryData)) {
      throw new Error("El formato de data.json no es válido.");
    }

    const userListNames = ["usuarios_seguridad_informatica", "usuarios_desarrollo_y_redes"];
    availableUsers = userListNames.flatMap((userListName) =>
      Array.isArray(directoryData[userListName]) ? directoryData[userListName].filter(isValidUser) : [],
    );
    if (availableUsers.length === 0) {
      throw new Error("No se encontraron usuarios válidos en data.json.");
    }

    loadAccessHistory(Array.isArray(directoryData.historial_accesos) ? directoryData.historial_accesos : []);
    loadFirewallHistory();
    loadLockoutState();
    renderAccessHistory();
    renderFirewallHistory();
    bindInterface();
    renderFiles();

    if (lockedUntil > Date.now()) {
      updateLockoutStatus();
      lockoutInterval = setInterval(updateLockoutStatus, 1000);
    } else {
      showStatus(
        failedAttempts > 0
          ? `Introduce tus credenciales. Te quedan ${maxFailedAttempts - failedAttempts} intentos.`
          : "Ingresa tu ID, nombre y clave de acceso.",
      );
    }

    try {
      fileDatabase = await openFileDatabase();
      files = await readSavedFiles();
      if (!files.every((file) => file && typeof file.id === "string" && typeof file.name === "string" && file.sourceFile instanceof Blob)) {
        throw new Error("Los archivos guardados tienen un formato no válido.");
      }
    } catch (error) {
      fileStorageError = error;
      files = [];
      console.error("No se pudo inicializar el almacenamiento persistente de archivos:", error);
    }
    renderFiles();

    if (fileStorageError) {
      showStatus("No se pudo habilitar el almacenamiento persistente de archivos en este navegador.", "error");
    }
    if (!persistentStorageAvailable) {
      showStatus(
        "Modo local: el navegador restringe el almacenamiento; el historial y los intentos solo durarán mientras esta página permanezca abierta.",
      );
    }
  } catch (error) {
    console.error("No se pudo inicializar BaultSafe:", error);
    if (location.protocol === "file:") {
      showStatus(
        `No se pudo iniciar BaultSafe desde index.html: ${error.message}.`,
        "error",
      );
    } else if (error instanceof DOMException && error.name === "SecurityError") {
      showStatus(
        "El navegador bloqueó el almacenamiento local. Habilítalo para este sitio y vuelve a cargar la página.",
        "error",
      );
    } else {
      showStatus(
        `No se pudo iniciar BaultSafe: ${error.message}. Comprueba que data.json sea válido y que el almacenamiento del navegador esté disponible.`,
        "error",
      );
    }
    setLoginDisabled(true);
  }
}

accessForm.addEventListener("submit", handleLogin);
initialize();
