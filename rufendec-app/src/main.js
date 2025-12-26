// Tauri API
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event || window.__TAURI__?.core?.event || {};
const { open } = window.__TAURI__.dialog || {};

let sourcePathEl;
let targetPathEl;
let passwordEl;
let saltEl;
let operationEl;
let targetTypeEl;
let executeBtn;
let statusMsgEl;
let progressContainer;
let progressBar;
let progressText;
let progressDetails;
let progressMessage;
let verboseContainer;
let verboseLog;
let isOperationComplete = false;

async function browseSource() {
  const targetType = document.querySelector('input[name="targetType"]:checked').value;
  
  try {
    let selected;
    if (targetType === 'directory') {
      selected = await open({
        directory: true,
        multiple: false,
        title: 'Select Source Directory'
      });
    } else {
      selected = await open({
        multiple: false,
        title: 'Select Source File'
      });
    }
    
    if (selected) {
      const path = Array.isArray(selected) ? selected[0] : selected;
      sourcePathEl.value = path;
      
      // Scan and display operational info immediately
      await scanOperationalInfo(path, targetType === 'directory');
    }
  } catch (error) {
    console.error('Error selecting source:', error);
    statusMsgEl.textContent = `Error: ${error}`;
  }
}

async function scanOperationalInfo(sourcePath, isDirectory) {
  try {
    await invoke('scan_operational_info', {
      sourcePath: sourcePath,
      isDirectory: isDirectory
    });
  } catch (error) {
    console.error('Error scanning operational info:', error);
    // Hide operational info on error
    document.getElementById('operational-info').style.display = 'none';
  }
}

async function browseTarget() {
  try {
    const selected = await open({
      directory: true,
      multiple: false,
      title: 'Select Target Directory'
    });
    
    if (selected) {
      targetPathEl.value = Array.isArray(selected) ? selected[0] : selected;
    }
  } catch (error) {
    console.error('Error selecting target:', error);
    statusMsgEl.textContent = `Error: ${error}`;
  }
}

async function execute() {
  if (!sourcePathEl.value) {
    statusMsgEl.textContent = 'Error: Please select a source path';
    statusMsgEl.className = 'error';
    return;
  }

  if (!passwordEl.value || !saltEl.value) {
    statusMsgEl.textContent = 'Error: Please enter both password and salt';
    statusMsgEl.className = 'error';
    return;
  }

  const targetType = document.querySelector('input[name="targetType"]:checked').value;
  const operation = document.querySelector('input[name="operation"]:checked').value;
  
  const options = {
    source_path: sourcePathEl.value,
    target_path: targetPathEl.value || null,
    password: passwordEl.value,
    salt: saltEl.value,
    operation: operation,
    mode: document.getElementById('mode').value,
    hash_with: document.getElementById('hash-with').value,
    iterations: parseInt(document.getElementById('iterations').value) || 10,
    threads: parseInt(document.getElementById('threads').value) || 8,
    delete_src: document.getElementById('delete-src').checked,
    anon: document.getElementById('anon').checked,
    dry_run: document.getElementById('dry-run').checked,
    verbose: document.getElementById('verbose').checked,
  };

  executeBtn.disabled = true;
  executeBtn.textContent = 'Processing...';
  statusMsgEl.textContent = 'Starting operation...';
  statusMsgEl.className = 'info';
  isOperationComplete = false;
  
  // Show progress bar
  progressContainer.style.display = 'block';
  progressBar.style.width = '0%';
  progressText.textContent = '0%';
  progressDetails.textContent = '0 / 0 files';
  progressMessage.textContent = 'Initializing...';
  
  // Show verbose log if verbose is enabled
  if (options.verbose) {
    verboseContainer.style.display = 'block';
    verboseLog.innerHTML = '';
    addVerboseLog('info', 'Starting operation...');
  } else {
    verboseContainer.style.display = 'none';
  }

  try {
    let result;
    if (targetType === 'directory') {
      result = await invoke('encrypt_directory', { options });
    } else {
      result = await invoke('encrypt_file', { options });
    }

    if (result.success) {
      statusMsgEl.textContent = `✓ ${result.message} (Success: ${result.success_count}, Failed: ${result.failed_count})`;
      statusMsgEl.className = 'success';
      isOperationComplete = true;
      
      // Update progress to show completion
      progressBar.style.width = '100%';
      progressText.textContent = '100%';
      const totalFiles = result.success_count + result.failed_count;
      progressDetails.textContent = `${totalFiles} / ${totalFiles} files`;
      progressMessage.textContent = 'Operation completed successfully';
      
      if (options.verbose) {
        addVerboseLog('info', `Operation completed successfully: ${result.message}`);
        // Add empty lines for better visibility
        for (let i = 0; i < 3; i++) {
          const spacer = document.createElement('div');
          spacer.style.height = '10px';
          verboseLog.appendChild(spacer);
        }
        verboseLog.scrollTop = verboseLog.scrollHeight;
      }
    } else {
      statusMsgEl.textContent = `⚠ ${result.message} (Success: ${result.success_count}, Failed: ${result.failed_count})`;
      statusMsgEl.className = 'warning';
      isOperationComplete = true;
      
      // Update progress to show completion (even with warnings)
      progressBar.style.width = '100%';
      progressText.textContent = '100%';
      const totalFiles = result.success_count + result.failed_count;
      progressDetails.textContent = `${totalFiles} / ${totalFiles} files`;
      progressMessage.textContent = 'Operation completed with warnings';
      
      if (options.verbose) {
        addVerboseLog('warn', `Operation completed with warnings: ${result.message}`);
      }
    }
  } catch (error) {
    console.error('Error executing operation:', error);
    statusMsgEl.textContent = `Error: ${error}`;
    statusMsgEl.className = 'error';
    isOperationComplete = true;
    
    // Update progress to show error state
    progressMessage.textContent = 'Operation failed';
    
    // Always show verbose log for errors, even if verbose mode wasn't enabled
    verboseContainer.style.display = 'block';
    addVerboseLog('error', `Operation failed: ${error}`);
  } finally {
    executeBtn.disabled = false;
    executeBtn.textContent = 'Execute';
    
    // Clear sensitive fields for security
    passwordEl.value = '';
    saltEl.value = '';
  }
}

function addVerboseLog(level, message) {
  const entry = document.createElement('div');
  entry.className = `log-entry ${level}`;
  const timestamp = new Date().toLocaleTimeString();
  entry.textContent = `[${timestamp}] ${message}`;
  verboseLog.appendChild(entry);
  // Auto-scroll to bottom
  verboseLog.scrollTop = verboseLog.scrollHeight;
}

window.addEventListener("DOMContentLoaded", async () => {
  sourcePathEl = document.getElementById('source-path');
  targetPathEl = document.getElementById('target-path');
  passwordEl = document.getElementById('password');
  saltEl = document.getElementById('salt');
  operationEl = document.querySelectorAll('input[name="operation"]');
  targetTypeEl = document.querySelectorAll('input[name="targetType"]');
  executeBtn = document.getElementById('execute-btn');
  statusMsgEl = document.getElementById('status-msg');
  
  // Progress bar elements
  progressContainer = document.getElementById('progress-container');
  progressBar = document.getElementById('progress-bar');
  progressText = document.getElementById('progress-text');
  progressDetails = document.getElementById('progress-details');
  progressMessage = document.getElementById('progress-message');
  
  // Verbose log elements
  verboseContainer = document.getElementById('verbose-container');
  verboseLog = document.getElementById('verbose-log');

  document.getElementById('browse-source').addEventListener('click', browseSource);
  document.getElementById('browse-target').addEventListener('click', browseTarget);
  executeBtn.addEventListener('click', execute);
  
  // GitHub link - try opening in Tauri webview, fallback to browser
  const githubLink = document.getElementById('github-link');
  if (githubLink) {
    githubLink.addEventListener('click', async (e) => {
      e.preventDefault();
      const githubUrl = 'https://github.com/omkarium/rufendec';
      
      try {
        // Try to create a new Tauri window via Rust command
        await invoke('open_github_window');
        return; // Success, window created
      } catch (error) {
        console.log('Failed to create Tauri window, falling back to browser:', error);
      }
      
      // Fallback: open in default browser
      try {
        if (window.__TAURI__?.shell?.open) {
          await window.__TAURI__.shell.open(githubUrl);
        } else {
          window.open(githubUrl, '_blank');
        }
      } catch (error) {
        console.error('Error opening GitHub link in browser:', error);
        window.open(githubUrl, '_blank');
      }
    });
  }
  
  // Clear log button
  document.getElementById('clear-log-btn').addEventListener('click', () => {
    verboseLog.innerHTML = '';
  });

  // Collapsible Advanced Options
  const advancedToggle = document.getElementById('advanced-toggle');
  const advancedContent = document.getElementById('advanced-content');
  
  // Start collapsed by default
  advancedToggle.classList.add('collapsed');
  advancedContent.classList.add('collapsed');
  
  advancedToggle.addEventListener('click', () => {
    advancedToggle.classList.toggle('collapsed');
    advancedContent.classList.toggle('collapsed');
  });

    // Operational info elements
    const operationalInfoEl = document.getElementById('operational-info');
    const infoOsEl = document.getElementById('info-os');
    const infoFilesEl = document.getElementById('info-files');
    const infoFoldersEl = document.getElementById('info-folders');
    const infoSizeEl = document.getElementById('info-size');

    // Listen for progress updates from Rust
    try {
      const unlistenProgress = await listen('progress-update', (event) => {
        // Don't update progress if operation is already complete
        if (isOperationComplete) {
          return;
        }
        
        const progress = event.payload;
        const percentage = Math.min(100, Math.max(0, progress.percentage));
        
        progressBar.style.width = `${percentage}%`;
        progressText.textContent = `${Math.round(percentage)}%`;
        progressDetails.textContent = `${progress.current} / ${progress.total} files`;
        progressMessage.textContent = progress.message;
      });
      
      // Listen for verbose messages from Rust
      const unlistenVerbose = await listen('verbose-message', (event) => {
        const verboseMsg = event.payload;
        // Always show verbose container for error messages
        if (verboseMsg.level === 'error') {
          verboseContainer.style.display = 'block';
        }
        addVerboseLog(verboseMsg.level || 'info', verboseMsg.message);
      });
      
      // Listen for show-verbose-container event
      const unlistenShowVerbose = await listen('show-verbose-container', () => {
        verboseContainer.style.display = 'block';
      });
      
      // Listen for operational info from Rust
      const unlistenOperationalInfo = await listen('operational-info', (event) => {
        const info = event.payload;
        infoOsEl.textContent = info.operating_system;
        infoFilesEl.textContent = info.file_count.toLocaleString();
        infoFoldersEl.textContent = info.folder_count.toLocaleString();
        infoSizeEl.textContent = info.total_size_human;
        operationalInfoEl.style.display = 'block';
      });
      
      // Store unlisten functions for cleanup if needed
      window.progressUnlisten = unlistenProgress;
      window.verboseUnlisten = unlistenVerbose;
      window.showVerboseUnlisten = unlistenShowVerbose;
      window.operationalInfoUnlisten = unlistenOperationalInfo;
    } catch (error) {
      console.error('Failed to listen for events:', error);
    }

  // Show/hide threads input based on target type
  targetTypeEl.forEach(radio => {
    radio.addEventListener('change', () => {
      const threadsGroup = document.getElementById('threads-group');
      if (radio.value === 'file') {
        threadsGroup.style.display = 'none';
      } else {
        threadsGroup.style.display = 'block';
      }
      
      // Update operational info if source path is set
      if (sourcePathEl.value) {
        scanOperationalInfo(sourcePathEl.value, radio.value === 'directory');
      }
    });
  });
  
  // Update operational info when source path is manually changed
  sourcePathEl.addEventListener('change', () => {
    if (sourcePathEl.value) {
      const targetType = document.querySelector('input[name="targetType"]:checked').value;
      scanOperationalInfo(sourcePathEl.value, targetType === 'directory');
    } else {
      document.getElementById('operational-info').style.display = 'none';
    }
  });
});
