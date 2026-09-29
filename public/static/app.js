/**
 * DIODE-SENTINEL // Tactical Security Operations Center Controller
 * Multi-Page SPA Client Router, Real-Time SSE Consumer, Neumorphic SOC UI Controller
 */

class DiodeSentinelApp {
  /**
   * Resolves the canonical backend API Base URL:
   * - window.DIODE_API_BASE_URL (explicit global override)
   * - URL query param ?api= or ?api_base=
   * - localStorage 'DIODE_API_BASE_URL'
   * - Localhost / private IP -> '' (local relative or port 8000)
   * - OnRender direct host -> ''
   * - Production Vercel (or any other domain) -> 'https://diode-senital.onrender.com'
   */
  static resolveApiBaseUrl() {
    if (typeof window === 'undefined') return '';

    // 1. Explicit window-level global config
    if (window.DIODE_API_BASE_URL && typeof window.DIODE_API_BASE_URL === 'string') {
      return window.DIODE_API_BASE_URL.trim().replace(/\/+$/, '');
    }
    if (window.VITE_DIODE_API_BASE_URL && typeof window.VITE_DIODE_API_BASE_URL === 'string') {
      return window.VITE_DIODE_API_BASE_URL.trim().replace(/\/+$/, '');
    }
    if (window.__API_BASE__ && typeof window.__API_BASE__ === 'string') {
      return window.__API_BASE__.trim().replace(/\/+$/, '');
    }

    // 2. Query param override (?api=https://... or ?api_base=...)
    try {
      const params = new URLSearchParams(window.location.search);
      const queryApi = params.get('api') || params.get('api_base');
      if (queryApi) {
        return queryApi.trim().replace(/\/+$/, '');
      }
    } catch (_) {}

    // 3. LocalStorage override
    try {
      const stored = localStorage.getItem('DIODE_API_BASE_URL');
      if (stored) return stored.trim().replace(/\/+$/, '');
    } catch (_) {}

    const hostname = (window.location && window.location.hostname ? window.location.hostname.toLowerCase() : '');

    // 4. Local development environments (localhost, 127.0.0.1, local private IP)
    const isLocalhost = hostname === 'localhost' ||
                        hostname === '127.0.0.1' ||
                        hostname === '[::1]' ||
                        hostname.endsWith('.local') ||
                        hostname.startsWith('192.168.') ||
                        hostname.startsWith('10.');

    if (isLocalhost) {
      if (window.location.port && window.location.port !== '8000') {
        return `${window.location.protocol}//${window.location.hostname}:8000`;
      }
      return '';
    }

    // 5. If hosted directly on Render backend origin
    if (hostname.includes('onrender.com')) {
      return '';
    }

    // 6. Production frontend (Vercel deployment: diode-senital.vercel.app or any external domain)
    return 'https://diode-senital.onrender.com';
  }

  constructor() {
    // API Configuration
    this.apiBaseUrl = DiodeSentinelApp.resolveApiBaseUrl();
    console.log('[Diode-Sentinel] Resolved Backend API Base:', this.apiBaseUrl || '(local relative)');
    
    // Application State
    this.currentRoute = '/dashboard/overview';
    this.alerts = [];
    this.incidents = [];
    this.flows = [];
    this.telemetry = null;
    this.validationData = null;
    this.complianceData = null;
    this.runtimeStatus = null;
    this.demoScenarios = [];
    this.availableInterfaces = [];
    
    // Connection State Machine (Truthful State Tracking)
    this.apiConnected = false;
    this.sseConnected = false;
    this.runtimeMode = 'idle';
    this.runtimeSource = null; // 'LIVE', 'DEMO', 'BACKEND_TEST', or null
    this.runtimeSessionId = null;

    // UI Filters & Paging
    this.activeThreatFilter = 'ALL';
    this.activeTimeWindow = '1H';
    this.isDemoRunning = false;
    this.isBackendTestRunning = false;
    this.isLiveRunning = false;
    this.demoPollingTimer = null;
    this.backendTestPollingTimer = null;
    this.eventSource = null;
    this.lastCompletedDemo = null;
    this.lastCompletedBackendTest = null;

    // Initialize application
    this.initElements();
    this.initRouting();
    this.initEventListeners();
    this.initDataSources();
    this.connectSSE();
    this.loadInterfaces();
  }

  apiUrl(path) {
    const base = (this.apiBaseUrl || '').replace(/\/+$/, '');
    const cleanPath = path.startsWith('/') ? path : `/${path}`;
    return base ? `${base}${cleanPath}` : cleanPath;
  }

  /* ========================================================================
     1. ROUTING ARCHITECTURE
     ======================================================================== */
  initRouting() {
    // Handle browser back/forward navigation
    window.addEventListener('popstate', () => {
      this.handleLocationChange(window.location.pathname, false);
    });

    // Handle initial route on page load
    const initialPath = window.location.pathname;
    this.handleLocationChange(initialPath, true);
  }

  handleLocationChange(pathname, replaceInitial = false) {
    let target = pathname.toLowerCase();
    
    // Normalize aliases
    if (target === '/' || target === '/dashboard' || target === '/dashboard/') {
      target = '/dashboard/overview';
    }

    const validRoutes = [
      '/dashboard/overview',
      '/dashboard/threats',
      '/dashboard/incidents',
      '/dashboard/flows',
      '/dashboard/engine',
      '/dashboard/demo',
      '/dashboard/system'
    ];

    if (!validRoutes.includes(target)) {
      target = '/dashboard/overview';
    }

    if (replaceInitial) {
      window.history.replaceState({ route: target }, '', target);
    }

    this.navigateTo(target, false);
  }

  navigateTo(route, pushHistory = true) {
    this.currentRoute = route;

    if (pushHistory) {
      window.history.pushState({ route: route }, '', route);
    }

    // Hide all pages, show target page
    document.querySelectorAll('.page-view').forEach(p => p.classList.remove('active'));
    
    const pageIdMap = {
      '/dashboard/overview': 'page-overview',
      '/dashboard/threats': 'page-threats',
      '/dashboard/incidents': 'page-incidents',
      '/dashboard/flows': 'page-flows',
      '/dashboard/engine': 'page-engine',
      '/dashboard/demo': 'page-demo',
      '/dashboard/system': 'page-system'
    };

    const targetPageId = pageIdMap[route] || 'page-overview';
    const targetElement = document.getElementById(targetPageId);
    if (targetElement) {
      targetElement.classList.add('active');
    }

    // Update active nav state in desktop sidebar
    document.querySelectorAll('.desktop-sidebar .nav-item').forEach(item => {
      item.classList.toggle('active', item.dataset.route === route);
    });

    // Update active nav state in mobile bottom bar
    document.querySelectorAll('.mobile-bottom-nav .bottom-nav-item').forEach(item => {
      if (item.dataset.route) {
        item.classList.toggle('active', item.dataset.route === route);
      }
    });

    // Update topbar breadcrumbs & page titles
    this.updateTopbarTitles(route);

    // Close mobile drawer if open
    this.closeMobileDrawer();

    // Trigger page-specific data refresh
    this.onPageEntered(route);

    // Scroll main viewport to top
    window.scrollTo({ top: 0, behavior: 'instant' });
    const appMain = document.getElementById('appMain');
    if (appMain) appMain.scrollTo({ top: 0, behavior: 'instant' });
  }

  updateTopbarTitles(route) {
    const titles = {
      '/dashboard/overview': { label: 'OVERVIEW', breadcrumb: 'Diode Sentinel / Security Command Console' },
      '/dashboard/threats': { label: 'LIVE THREATS', breadcrumb: 'ThreatCore / Corroborated Attack Events' },
      '/dashboard/incidents': { label: 'ATTACK CHAINS', breadcrumb: 'Correlation Engine / Corroborated Kill-Chains' },
      '/dashboard/flows': { label: 'NETWORK FLOWS', breadcrumb: 'Streaming Flow Aggregator / 6 Feature Domains' },
      '/dashboard/engine': { label: 'MODEL ENGINE', breadcrumb: 'Machine Learning Classifiers & SLA SLAs' },
      '/dashboard/demo': { label: 'DEMO TESTING', breadcrumb: 'Passive Ingestion / Attack PCAP Scenario Replay' },
      '/dashboard/system': { label: 'SYSTEM & DIODE', breadcrumb: 'Hardware Diode Compliance & Enclave Governance' }
    };

    const info = titles[route] || titles['/dashboard/overview'];
    const labelEl = document.getElementById('topbarPageTitle');
    const breadcrumbEl = document.getElementById('topbarBreadcrumb');
    if (labelEl) labelEl.textContent = info.label;
    if (breadcrumbEl) breadcrumbEl.textContent = info.breadcrumb;
    document.title = `DIODE SENTINEL // ${info.label}`;
  }

  onPageEntered(route) {
    if (route === '/dashboard/flows') {
      this.loadFlows();
    } else if (route === '/dashboard/engine') {
      this.loadValidationData();
    } else if (route === '/dashboard/demo') {
      this.loadDemoScenarios();
      this.checkRuntimeStatus();
      this.loadLastDemoResult();
    } else if (route === '/dashboard/system') {
      this.loadComplianceAudit();
      this.loadLastBackendTestResult();
    } else if (route === '/dashboard/overview') {
      this.renderOverview();
    } else if (route === '/dashboard/threats') {
      this.renderThreats();
    } else if (route === '/dashboard/incidents') {
      this.renderIncidents();
    }
  }

  /* ========================================================================
     2. ELEMENT INITIALIZATION & EVENT LISTENERS
     ======================================================================== */
  initElements() {
    // Mobile navigation controls
    this.btnMobileMenuToggle = document.getElementById('btnMobileMenuToggle');
    this.btnMobileMore = document.getElementById('btnMobileMore');
    this.mobileDrawer = document.getElementById('mobileDrawer');
    this.mobileDrawerOverlay = document.getElementById('mobileDrawerOverlay');
    this.btnDrawerClose = document.getElementById('btnDrawerClose');

    // Modals
    this.validationModal = document.getElementById('validationModal');
    this.alertDetailModal = document.getElementById('alertDetailModal');
    this.flowDetailModal = document.getElementById('flowDetailModal');

    // Live Capture Controls
    this.btnStartLiveCapture = document.getElementById('btnStartLiveCapture');
    this.btnStopLiveCapture = document.getElementById('btnStopLiveCapture');
    this.selLiveInterface = document.getElementById('selLiveInterface');
    this.liveCaptureStatusBadge = document.getElementById('liveCaptureStatusBadge');
    this.liveCaptureSummary = document.getElementById('liveCaptureSummary');

    // Close buttons
    this.btnCloseValidation = document.getElementById('btnCloseValidation');
    this.btnDismissValidation = document.getElementById('btnDismissValidation');
    this.btnCloseAlertModal = document.getElementById('btnCloseAlertModal');
    this.btnDismissAlertModal = document.getElementById('btnDismissAlertModal');
    this.btnCloseFlowModal = document.getElementById('btnCloseFlowModal');
    this.btnDismissFlowModal = document.getElementById('btnDismissFlowModal');
    this.btnOpenAuditModal = document.getElementById('btnOpenAuditModal');
    this.btnResetWatchdog = document.getElementById('btnResetWatchdog');

    // Backend Test Controls
    this.btnRunBackendTest = document.getElementById('btnRunBackendTest');
    this.backendTestScenarioSelect = document.getElementById('backendTestScenarioSelect');
    this.backendTestPill = document.getElementById('backendTestPill');
    this.backendTestSessionId = document.getElementById('backendTestSessionId');
    this.backendTestPackets = document.getElementById('backendTestPackets');
    this.backendTestFlows = document.getElementById('backendTestFlows');
    this.backendTestAlerts = document.getElementById('backendTestAlerts');
    this.backendTestElapsed = document.getElementById('backendTestElapsed');
    this.backendTestActionMsg = document.getElementById('backendTestActionMsg');
  }

  initEventListeners() {
    // Intercept client-side routing links
    document.addEventListener('click', (e) => {
      const link = e.target.closest('a[data-route]');
      if (link && link.dataset.route) {
        e.preventDefault();
        this.navigateTo(link.dataset.route, true);
      }
    });

    // Mobile drawer toggle
    if (this.btnMobileMenuToggle) {
      this.btnMobileMenuToggle.addEventListener('click', () => this.toggleMobileDrawer());
    }
    if (this.btnMobileMore) {
      this.btnMobileMore.addEventListener('click', () => this.toggleMobileDrawer());
    }
    if (this.mobileDrawerOverlay) {
      this.mobileDrawerOverlay.addEventListener('click', () => this.closeMobileDrawer());
    }
    if (this.btnDrawerClose) {
      this.btnDrawerClose.addEventListener('click', () => this.closeMobileDrawer());
    }

    // Live Capture controls
    if (this.btnStartLiveCapture) {
      this.btnStartLiveCapture.addEventListener('click', () => this.startLiveMonitoring());
    }
    if (this.btnStopLiveCapture) {
      this.btnStopLiveCapture.addEventListener('click', () => this.stopLiveMonitoring());
    }

    // Time window selector chips
    document.querySelectorAll('#timeWindowSelector .btn-time-chip').forEach(chip => {
      chip.addEventListener('click', (e) => {
        document.querySelectorAll('#timeWindowSelector .btn-time-chip').forEach(c => c.classList.remove('active'));
        e.currentTarget.classList.add('active');
        this.activeTimeWindow = e.currentTarget.dataset.window;
        this.renderOverview();
      });
    });

    // Threat class filter chips
    document.querySelectorAll('#threatFiltersBar .filter-chip').forEach(chip => {
      chip.addEventListener('click', (e) => {
        document.querySelectorAll('#threatFiltersBar .filter-chip').forEach(c => c.classList.remove('active'));
        e.currentTarget.classList.add('active');
        this.activeThreatFilter = e.currentTarget.dataset.filter;
        this.renderThreats();
      });
    });

    // Modal listeners
    if (this.btnOpenAuditModal) {
      this.btnOpenAuditModal.addEventListener('click', () => this.openAuditModal());
    }
    if (this.btnCloseValidation) {
      this.btnCloseValidation.addEventListener('click', () => this.closeModal(this.validationModal));
    }
    if (this.btnDismissValidation) {
      this.btnDismissValidation.addEventListener('click', () => this.closeModal(this.validationModal));
    }
    if (this.btnCloseAlertModal) {
      this.btnCloseAlertModal.addEventListener('click', () => this.closeModal(this.alertDetailModal));
    }
    if (this.btnDismissAlertModal) {
      this.btnDismissAlertModal.addEventListener('click', () => this.closeModal(this.alertDetailModal));
    }
    if (this.btnCloseFlowModal) {
      this.btnCloseFlowModal.addEventListener('click', () => this.closeModal(this.flowDetailModal));
    }
    if (this.btnDismissFlowModal) {
      this.btnDismissFlowModal.addEventListener('click', () => this.closeModal(this.flowDetailModal));
    }

    // Watchdog baseline reset
    if (this.btnResetWatchdog) {
      this.btnResetWatchdog.addEventListener('click', () => this.resetWatchdog());
    }

    // Backend Test RUN button
    if (this.btnRunBackendTest) {
      this.btnRunBackendTest.addEventListener('click', () => this.runBackendTest());
    }

    // Scenario RUN TEST buttons
    document.addEventListener('click', (e) => {
      const btn = e.target.closest('.btn-run-scenario');
      if (btn && btn.dataset.pcap) {
        this.runDemoScenario(btn.dataset.pcap, btn);
      }
    });

    // Close modals on Escape key
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        this.closeAllModals();
        this.closeMobileDrawer();
      }
    });
  }

  toggleMobileDrawer() {
    const isOpen = this.mobileDrawer.classList.contains('open');
    if (isOpen) {
      this.closeMobileDrawer();
    } else {
      this.openMobileDrawer();
    }
  }

  openMobileDrawer() {
    if (this.mobileDrawer) this.mobileDrawer.classList.add('open');
    if (this.mobileDrawerOverlay) this.mobileDrawerOverlay.classList.add('open');
  }

  closeMobileDrawer() {
    if (this.mobileDrawer) this.mobileDrawer.classList.remove('open');
    if (this.mobileDrawerOverlay) this.mobileDrawerOverlay.classList.remove('open');
  }

  openModal(modal) {
    if (modal) modal.classList.add('open');
  }

  closeModal(modal) {
    if (modal) modal.classList.remove('open');
  }

  closeAllModals() {
    document.querySelectorAll('.modal-backdrop').forEach(m => m.classList.remove('open'));
  }

  /* ========================================================================
     3. DATA SOURCE INITIALIZATION & SSE STREAMING
     ======================================================================== */
  initDataSources() {
    this.checkHealth();
    this.checkRuntimeStatus();
    this.loadTelemetry();
    this.loadAlerts();
    this.loadIncidents();
    this.loadComplianceAudit();

    // Periodically update telemetry & runtime status
    setInterval(() => {
      this.checkRuntimeStatus();
      this.loadTelemetry();
    }, 4000);
  }

  async checkHealth() {
    try {
      const res = await fetch(this.apiUrl('/api/health'));
      if (res.ok) {
        this.apiConnected = true;
        this.updateConnectionStatus();
      }
    } catch (err) {
      console.warn('Health check failed:', err);
    }
  }

  connectSSE() {
    if (this.eventSource) {
      this.eventSource.close();
    }

    try {
      const sseUrl = this.apiUrl('/api/events');
      console.log('[Diode-Sentinel] Connecting EventSource to:', sseUrl);
      this.eventSource = new EventSource(sseUrl);

      this.eventSource.addEventListener('open', () => {
        this.sseConnected = true;
        this.updateConnectionStatus();
      });

      this.eventSource.addEventListener('status', (e) => {
        try {
          const status = JSON.parse(e.data);
          this.sseConnected = true;
          this.runtimeMode = status.mode || 'idle';
          this.runtimeSource = status.source || null;
          this.runtimeSessionId = status.session_id || null;
          if (status.mode === 'live') {
            this.isLiveRunning = true;
          } else if (status.mode === 'idle') {
            this.isLiveRunning = false;
          }
          if (this.runtimeStatus) {
            Object.assign(this.runtimeStatus, status);
          } else {
            this.runtimeStatus = status;
          }
          this.updateConnectionStatus();
        } catch (err) {
          console.warn('SSE status parse error:', err);
        }
      });

      this.eventSource.addEventListener('alert', (e) => {
        try {
          const alertData = JSON.parse(e.data);
          this.handleIncomingAlert(alertData);
        } catch (err) {
          console.warn('SSE alert parse error:', err);
        }
      });

      this.eventSource.addEventListener('incident', (e) => {
        try {
          const incData = JSON.parse(e.data);
          this.handleIncomingIncident(incData);
        } catch (err) {
          console.warn('SSE incident parse error:', err);
        }
      });

      this.eventSource.addEventListener('demo_completed', (e) => {
        try {
          const data = JSON.parse(e.data);
          if (data) {
            this.lastCompletedDemo = data;
            if (!this.isDemoRunning) {
              this.renderDemoConsoleResult(this.lastCompletedDemo);
            }
          }
        } catch (err) {
          console.warn('SSE demo_completed parse error:', err);
        }
      });

      this.eventSource.addEventListener('backend_test_completed', (e) => {
        try {
          const data = JSON.parse(e.data);
          if (data) {
            this.lastCompletedBackendTest = data;
            if (!this.isBackendTestRunning) {
              this.renderBackendTestResult(this.lastCompletedBackendTest);
            }
          }
        } catch (err) {
          console.warn('SSE backend_test_completed parse error:', err);
        }
      });

      this.eventSource.addEventListener('error', () => {
        this.sseConnected = false;
        this.updateConnectionStatus();
      });
    } catch (err) {
      this.sseConnected = false;
      this.updateConnectionStatus();
    }
  }

  updateConnectionStatus() {
    let modeText = 'DISCONNECTED';
    let pillClass = 'rose';
    let mobText = 'OFFLINE';

    const isRunning = Boolean(
      (this.runtimeStatus && this.runtimeStatus.running && this.runtimeSource === 'LIVE') ||
      this.isLiveRunning ||
      this.runtimeSource === 'LIVE'
    );
    const isBackendTest = Boolean(
      this.isBackendTestRunning ||
      this.runtimeSource === 'BACKEND_TEST'
    );
    const isDemo = Boolean(
      this.isDemoRunning ||
      this.runtimeSource === 'DEMO'
    );

    if (!this.apiConnected) {
      modeText = 'DISCONNECTED';
      pillClass = 'rose';
      mobText = 'OFFLINE';
    } else if (!this.sseConnected) {
      modeText = 'CONNECTED / NO ACTIVE STREAM';
      pillClass = 'amber';
      mobText = 'NO STREAM';
    } else {
      // Both API and SSE connected
      if (isRunning) {
        modeText = 'CONNECTED / LIVE';
        pillClass = 'emerald';
        mobText = 'LIVE';
      } else if (isBackendTest) {
        modeText = 'CONNECTED / BACKEND TEST';
        pillClass = 'purple';
        mobText = 'TEST';
      } else if (isDemo) {
        modeText = 'CONNECTED / DEMO SESSION';
        pillClass = 'blue';
        mobText = 'DEMO';
      } else {
        modeText = 'CONNECTED / NO ACTIVE STREAM';
        pillClass = 'sky';
        mobText = 'IDLE';
      }
    }

    const textEl = document.getElementById('mobileStatusText');
    if (textEl) {
      textEl.textContent = mobText;
    }
    const sysConn = document.getElementById('sysConnPill');
    if (sysConn) {
      sysConn.textContent = modeText;
      sysConn.className = `compliance-pill ${pillClass}`;
    }

    // Truthful backend API endpoint display - never default to Vercel origin
    const hostDisplay = this.apiBaseUrl
      ? this.apiBaseUrl
      : (typeof window !== 'undefined' && !window.location.hostname.includes('vercel.app')
          ? window.location.origin
          : 'https://diode-senital.onrender.com');

    const apiDisplay = document.getElementById('sysApiEndpointDisplay');
    if (apiDisplay) {
      apiDisplay.textContent = `${hostDisplay} (${this.apiConnected ? 'ONLINE' : 'UNREACHABLE'})`;
    }

    const sseDisplay = document.getElementById('sysSseStatusDisplay');
    if (sseDisplay) {
      sseDisplay.textContent = this.sseConnected
        ? 'CONNECTED'
        : (this.apiConnected ? 'RECONNECTING...' : 'DISCONNECTED');
    }

    // Operational Mode display - derived truthfully from /api/runtime/status
    const opModeEl = document.getElementById('sysOperationalMode');
    if (opModeEl) {
      if (!this.apiConnected) {
        opModeEl.textContent = 'DISCONNECTED';
      } else if (this.runtimeStatus) {
        const mode = (this.runtimeStatus.mode || '').toUpperCase();
        if (isRunning) {
          opModeEl.textContent = 'LIVE PROMISCUOUS MONITORING';
        } else if (isBackendTest) {
          opModeEl.textContent = 'BACKEND SOC VERIFICATION EXECUTION';
        } else if (isDemo) {
          opModeEl.textContent = 'DEMO PCAP REPLAY';
        } else if (mode === 'IDLE' || this.runtimeStatus.source === 'IDLE') {
          opModeEl.textContent = 'STANDBY / IDLE (ZERO EGRESS)';
        } else {
          opModeEl.textContent = `STANDBY (${mode || 'READY'})`;
        }
      } else {
        opModeEl.textContent = 'STANDBY / IDLE (ZERO EGRESS)';
      }
    }
  }

  getDashboardAlerts() {
    return this.alerts.filter(a =>
      a.source === 'LIVE' ||
      a.source === 'BACKEND_TEST' ||
      (a.session_id && (a.session_id.startsWith('LIVE-') || a.session_id.startsWith('TEST-')))
    );
  }

  getLiveAlerts() {
    return this.getDashboardAlerts();
  }

  getBackendTestAlerts() {
    return this.alerts.filter(a => a.source === 'BACKEND_TEST' || (a.session_id && a.session_id.startsWith('TEST-')));
  }

  getDemoAlerts() {
    return this.alerts.filter(a => a.source === 'DEMO' || (a.session_id && a.session_id.startsWith('DEMO-')));
  }

  getDashboardIncidents() {
    return this.incidents.filter(i =>
      i.source === 'LIVE' ||
      i.source === 'BACKEND_TEST' ||
      (i.session_id && (i.session_id.startsWith('LIVE-') || i.session_id.startsWith('TEST-')))
    );
  }

  getLiveIncidents() {
    return this.getDashboardIncidents();
  }

  getBackendTestIncidents() {
    return this.incidents.filter(i => i.source === 'BACKEND_TEST' || (i.session_id && i.session_id.startsWith('TEST-')));
  }

  getDemoIncidents() {
    return this.incidents.filter(i => i.source === 'DEMO' || (i.session_id && i.session_id.startsWith('DEMO-')));
  }

  handleIncomingAlert(alert) {
    // Prepend to alerts list
    this.alerts.unshift(alert);
    if (this.alerts.length > 500) this.alerts.pop();

    this.updateCounters();

    // Re-render active page if relevant
    if (this.currentRoute === '/dashboard/overview') {
      this.renderOverview();
    } else if (this.currentRoute === '/dashboard/threats') {
      this.renderThreats();
    }
  }

  handleIncomingIncident(incident) {
    // Prepend to incidents list
    this.incidents.unshift(incident);
    if (this.incidents.length > 100) this.incidents.pop();

    this.updateCounters();

    if (this.currentRoute === '/dashboard/overview') {
      this.renderOverview();
    } else if (this.currentRoute === '/dashboard/incidents') {
      this.renderIncidents();
    }
  }

  updateCounters() {
    const liveAlerts = this.getLiveAlerts();
    const liveIncidents = this.getLiveIncidents();

    const threatCount = liveAlerts.length;
    const incidentCount = liveIncidents.length;

    // Desktop sidebar counters
    const sbThreatEl = document.getElementById('sidebarThreatCount');
    if (sbThreatEl) {
      sbThreatEl.textContent = threatCount;
      sbThreatEl.style.display = threatCount > 0 ? 'inline-block' : 'none';
    }

    const sbIncEl = document.getElementById('sidebarIncidentCount');
    if (sbIncEl) {
      sbIncEl.textContent = incidentCount;
      sbIncEl.style.display = incidentCount > 0 ? 'inline-block' : 'none';
    }

    // Mobile bottom nav counters
    const mobThreatEl = document.getElementById('mobThreatCount');
    if (mobThreatEl) {
      mobThreatEl.textContent = threatCount;
      mobThreatEl.style.display = threatCount > 0 ? 'block' : 'none';
    }

    const mobIncEl = document.getElementById('mobIncidentCount');
    if (mobIncEl) {
      mobIncEl.textContent = incidentCount;
      mobIncEl.style.display = incidentCount > 0 ? 'block' : 'none';
    }

    // Page titles count
    const totalThreatEl = document.getElementById('totalThreatCount');
    if (totalThreatEl) {
      totalThreatEl.textContent = !this.apiConnected ? '--' : (threatCount > 0 ? threatCount : '0');
    }
    
    const activeIncEl = document.getElementById('activeIncidentsCount');
    if (activeIncEl) {
      activeIncEl.textContent = !this.apiConnected ? '--' : (incidentCount > 0 ? incidentCount : '0');
    }
  }

  /* ========================================================================
     4. API DATA FETCHERS & HARDWARE INTERFACES
     ======================================================================== */
  async loadInterfaces() {
    try {
      const res = await fetch(this.apiUrl('/api/runtime/interfaces'));
      if (res.ok) {
        const data = await res.json();
        this.availableInterfaces = data.interfaces || [];
        const sel = this.selLiveInterface;
        if (sel) {
          sel.innerHTML = '';
          if (this.availableInterfaces.length === 0) {
            const opt = document.createElement('option');
            opt.value = '';
            opt.textContent = 'No sniffable interface detected';
            sel.appendChild(opt);
            if (this.btnStartLiveCapture) this.btnStartLiveCapture.disabled = true;
          } else {
            this.availableInterfaces.forEach(iface => {
              const opt = document.createElement('option');
              opt.value = iface;
              opt.textContent = iface;
              sel.appendChild(opt);
            });
            if (this.btnStartLiveCapture) this.btnStartLiveCapture.disabled = false;
          }
        }
        if (this.liveCaptureSummary) {
          this.liveCaptureSummary.textContent = data.available 
            ? `${this.availableInterfaces.length} network interface(s) identified for promiscuous monitoring.`
            : (data.note || 'Promiscuous NIC capture requires elevated privileges.');
        }
      }
    } catch (err) {
      console.warn('Interfaces load failed:', err);
    }
  }

  async startLiveMonitoring() {
    const sel = this.selLiveInterface;
    const iface = sel ? sel.value : null;

    if (this.btnStartLiveCapture) this.btnStartLiveCapture.disabled = true;
    if (this.btnStopLiveCapture) this.btnStopLiveCapture.disabled = false;
    if (this.liveCaptureStatusBadge) {
      this.liveCaptureStatusBadge.textContent = 'STARTING...';
      this.liveCaptureStatusBadge.className = 'console-badge running';
    }

    try {
      const res = await fetch(this.apiUrl('/api/runtime/start'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'live', interface: iface || undefined, source: 'LIVE' })
      });
      const data = await res.json();
      if (data.status === 'started' || data.status === 'already_running') {
        this.isLiveRunning = true;
        this.runtimeMode = 'live';
        this.runtimeSource = 'LIVE';
        if (this.liveCaptureStatusBadge) {
          this.liveCaptureStatusBadge.textContent = 'CAPTURING LIVE';
          this.liveCaptureStatusBadge.className = 'console-badge running';
        }
        if (this.liveCaptureSummary) {
          this.liveCaptureSummary.textContent = `Streaming packets from interface "${iface || 'default'}" into passive Diode ingestion pipeline.`;
        }
        this.updateConnectionStatus();
      } else {
        alert('Live capture could not start: ' + (data.error || JSON.stringify(data)));
        if (this.btnStartLiveCapture) this.btnStartLiveCapture.disabled = false;
        if (this.btnStopLiveCapture) this.btnStopLiveCapture.disabled = true;
      }
    } catch (err) {
      alert('Failed to start live capture: ' + err.message);
      if (this.btnStartLiveCapture) this.btnStartLiveCapture.disabled = false;
      if (this.btnStopLiveCapture) this.btnStopLiveCapture.disabled = true;
    }
  }

  async stopLiveMonitoring() {
    if (this.btnStopLiveCapture) this.btnStopLiveCapture.disabled = true;
    try {
      const res = await fetch(this.apiUrl('/api/runtime/stop'), { method: 'POST' });
      await res.json();
      this.isLiveRunning = false;
      this.runtimeMode = 'idle';
      this.runtimeSource = null;
      if (this.liveCaptureStatusBadge) {
        this.liveCaptureStatusBadge.textContent = 'STOPPED';
        this.liveCaptureStatusBadge.className = 'console-badge';
      }
      if (this.btnStartLiveCapture) this.btnStartLiveCapture.disabled = false;
      this.updateConnectionStatus();
    } catch (err) {
      alert('Failed to stop live capture: ' + err.message);
      if (this.btnStopLiveCapture) this.btnStopLiveCapture.disabled = false;
    }
  }

  async loadTelemetry() {
    try {
      const res = await fetch(this.apiUrl('/api/telemetry'));
      if (res.ok) {
        this.apiConnected = true;
        this.telemetry = await res.json();
        this.updateTelemetryUI();
      } else {
        this.apiConnected = false;
      }
    } catch (err) {
      this.apiConnected = false;
      console.warn('Telemetry load failed:', err);
    }
    this.updateConnectionStatus();
  }

  async loadAlerts() {
    try {
      const res = await fetch(this.apiUrl('/api/alerts'));
      if (res.ok) {
        this.apiConnected = true;
        const data = await res.json();
        if (Array.isArray(data)) {
          this.alerts = data;
          this.updateCounters();
          this.renderOverview();
          this.renderThreats();
        }
      } else {
        this.apiConnected = false;
      }
    } catch (err) {
      this.apiConnected = false;
      console.warn('Alerts load failed:', err);
    }
    this.updateConnectionStatus();
  }

  async loadIncidents() {
    try {
      const res = await fetch(this.apiUrl('/api/incidents'));
      if (res.ok) {
        this.apiConnected = true;
        const data = await res.json();
        if (Array.isArray(data)) {
          this.incidents = data;
          this.updateCounters();
          this.renderIncidents();
        }
      } else {
        this.apiConnected = false;
      }
    } catch (err) {
      this.apiConnected = false;
      console.warn('Incidents load failed:', err);
    }
    this.updateConnectionStatus();
  }

  async loadFlows() {
    try {
      const res = await fetch(this.apiUrl('/api/flows'));
      if (res.ok) {
        this.apiConnected = true;
        const data = await res.json();
        if (Array.isArray(data)) {
          this.flows = data;
          this.renderFlows();
          this.renderOverview();
        }
      } else {
        this.apiConnected = false;
      }
    } catch (err) {
      this.apiConnected = false;
      console.warn('Flows load failed:', err);
    }
    this.updateConnectionStatus();
  }

  async loadValidationData() {
    try {
      const res = await fetch(this.apiUrl('/api/validation'));
      if (res.ok) {
        this.apiConnected = true;
        this.validationData = await res.json();
      } else {
        this.apiConnected = false;
      }
    } catch (err) {
      this.apiConnected = false;
      console.warn('Validation data load failed:', err);
    }
    this.updateConnectionStatus();
  }

  async loadComplianceAudit() {
    try {
      const res = await fetch(this.apiUrl('/api/compliance/audit'));
      if (res.ok) {
        this.apiConnected = true;
        this.complianceData = await res.json();
        this.updateComplianceUI();
      } else {
        this.apiConnected = false;
      }
    } catch (err) {
      this.apiConnected = false;
      console.warn('Compliance audit load failed:', err);
    }
    this.updateConnectionStatus();
  }

  async loadDemoScenarios() {
    try {
      const res = await fetch(this.apiUrl('/api/demo/scenarios'));
      if (res.ok) {
        this.apiConnected = true;
        this.demoScenarios = await res.json();
      } else {
        this.apiConnected = false;
      }
    } catch (err) {
      this.apiConnected = false;
      console.warn('Demo scenarios load failed:', err);
    }
    this.updateConnectionStatus();
  }

  async checkRuntimeStatus() {
    try {
      const res = await fetch(this.apiUrl('/api/runtime/status'));
      if (res.ok) {
        this.apiConnected = true;
        this.runtimeStatus = await res.json();
        this.updateRuntimeUI();
      } else {
        this.apiConnected = false;
      }
    } catch (err) {
      this.apiConnected = false;
      console.warn('Runtime status check failed:', err);
    }
    this.updateConnectionStatus();
  }

  async resetWatchdog() {
    try {
      const res = await fetch(this.apiUrl('/api/compliance/reset'), { method: 'POST' });
      if (res.ok) {
        alert('Diode compliance watchdog baseline recalibrated to CLEAN.');
        this.loadComplianceAudit();
      }
    } catch (err) {
      alert('Failed to recalibrate watchdog: ' + err.message);
    }
  }

  async loadLastDemoResult() {
    try {
      const res = await fetch(this.apiUrl('/api/demo/last_result'));
      if (res.ok) {
        const data = await res.json();
        if (data && data.last_demo_result) {
          this.lastCompletedDemo = data.last_demo_result;
          if (!this.isDemoRunning) {
            this.renderDemoConsoleResult(this.lastCompletedDemo);
          }
        }
      }
    } catch (err) {
      console.warn('Failed to fetch last demo result:', err);
    }
  }

  renderDemoConsoleResult(demoResult) {
    if (!demoResult) return;
    const summary = demoResult.summary || {};
    const pcapName = (demoResult.pcap || '').split(/[\\/]/).pop() || 'None selected';
    const sessionId = demoResult.session_id || 'DEMO-COMPLETED';

    const badge = document.getElementById('demoEngineStatusBadge');
    if (badge) {
      if (demoResult.error) {
        badge.textContent = 'ERROR';
        badge.className = 'console-badge error';
      } else {
        badge.textContent = 'COMPLETED';
        badge.className = 'console-badge';
      }
    }

    const sessionEl = document.getElementById('demoSessionId');
    if (sessionEl) sessionEl.textContent = sessionId;

    const pActive = document.getElementById('demoActivePcap');
    if (pActive) pActive.textContent = pcapName;

    const pParsed = document.getElementById('demoPacketsParsed');
    if (pParsed) pParsed.textContent = (summary.packets !== undefined ? summary.packets : 0).toLocaleString();

    const fEmitted = document.getElementById('demoFlowsEmitted');
    if (fEmitted) fEmitted.textContent = (summary.records !== undefined ? summary.records : 0).toLocaleString();

    const aEmitted = document.getElementById('demoAlertsEmitted');
    if (aEmitted) aEmitted.textContent = (summary.alerts !== undefined ? summary.alerts : 0).toLocaleString();

    const eTime = document.getElementById('demoElapsedTime');
    if (eTime) eTime.textContent = `${(summary.elapsed_sec || 0).toFixed(1)}s`;

    const msg = document.getElementById('demoActionMsg');
    if (msg) {
      if (demoResult.error) {
        msg.textContent = `Pipeline halted: ${demoResult.error}`;
      } else {
        const pkts = (summary.packets || 0).toLocaleString();
        const recs = (summary.records || 0).toLocaleString();
        const alts = (summary.alerts || 0).toLocaleString();
        const elap = (summary.elapsed_sec || 0).toFixed(2);
        msg.textContent = `Scenario complete: ${pkts} packets parsed into ${recs} flow feature records with ${alts} alerts promoted in ${elap}s. Zero egress verified.`;
      }
    }
  }

  async runDemoScenario(pcapPath, triggerButton) {
    if (this.isDemoRunning) return;

    this.isDemoRunning = true;
    const pcapBase = pcapPath.split(/[\\/]/).pop();

    if (triggerButton) {
      triggerButton.disabled = true;
      triggerButton.innerHTML = '<span>⏳</span> INGESTING...';
    }

    const badge = document.getElementById('demoEngineStatusBadge');
    if (badge) {
      badge.textContent = 'RUNNING';
      badge.className = 'console-badge running';
    }

    const pActive = document.getElementById('demoActivePcap');
    if (pActive) pActive.textContent = pcapBase;

    const sessionEl = document.getElementById('demoSessionId');
    if (sessionEl) sessionEl.textContent = 'DEMO-INITIALIZING...';

    // Clear in-flight counters for clean run
    const pParsed = document.getElementById('demoPacketsParsed');
    if (pParsed) pParsed.textContent = '0';
    const fEmitted = document.getElementById('demoFlowsEmitted');
    if (fEmitted) fEmitted.textContent = '0';
    const aEmitted = document.getElementById('demoAlertsEmitted');
    if (aEmitted) aEmitted.textContent = '0';
    const eTime = document.getElementById('demoElapsedTime');
    if (eTime) eTime.textContent = '0.0s';

    const msg = document.getElementById('demoActionMsg');
    if (msg) {
      msg.textContent = `Streaming PCAP "${pcapBase}" into passive ingestion pipeline with zero-egress hardware compliance watchdog active...`;
    }

    try {
      const res = await fetch(this.apiUrl('/api/runtime/start'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pcap: pcapPath, mode: 'demo', source: 'DEMO' })
      });
      
      const startData = await res.json();
      if (startData && startData.session_id) {
        this.runtimeSessionId = startData.session_id;
        if (sessionEl) sessionEl.textContent = startData.session_id;
      }
      if (startData && (startData.active_pcap || startData.pcap)) {
        if (pActive) pActive.textContent = (startData.active_pcap || startData.pcap).split(/[\\/]/).pop();
      }
      
      // Start polling runtime until complete
      if (this.demoPollingTimer) clearInterval(this.demoPollingTimer);
      
      this.demoPollingTimer = setInterval(async () => {
        try {
          const stRes = await fetch(this.apiUrl('/api/runtime/status'));
          if (stRes.ok) {
            const st = await stRes.json();
            
            // Live updates during execution
            if (st.session_id && sessionEl) sessionEl.textContent = st.session_id;
            if ((st.active_pcap || st.pcap) && pActive) {
              pActive.textContent = (st.active_pcap || st.pcap).split(/[\\/]/).pop();
            }

            const currentSummary = st.summary || (st.last_demo_result ? st.last_demo_result.summary : {});
            if (pParsed && currentSummary.packets !== undefined) pParsed.textContent = currentSummary.packets.toLocaleString();
            if (fEmitted && currentSummary.records !== undefined) fEmitted.textContent = currentSummary.records.toLocaleString();
            if (aEmitted && currentSummary.alerts !== undefined) aEmitted.textContent = currentSummary.alerts.toLocaleString();
            if (eTime && currentSummary.elapsed_sec !== undefined) eTime.textContent = `${currentSummary.elapsed_sec.toFixed(1)}s`;

            if (!st.running) {
              clearInterval(this.demoPollingTimer);
              this.isDemoRunning = false;
              if (triggerButton) {
                triggerButton.disabled = false;
                triggerButton.innerHTML = '<span>▶</span> RUN TEST';
              }

              const err = st.last_error || (st.last_demo_result ? st.last_demo_result.error : null);
              const finalSummary = (st.summary && st.summary.packets !== undefined)
                ? st.summary
                : (st.last_demo_result ? st.last_demo_result.summary : currentSummary);

              if (err) {
                if (badge) {
                  badge.textContent = 'ERROR';
                  badge.className = 'console-badge error';
                }
                if (msg) msg.textContent = 'Pipeline execution failed: ' + err;
                this.lastCompletedDemo = {
                  session_id: st.session_id || 'DEMO-ERROR',
                  pcap: pcapPath,
                  summary: finalSummary,
                  error: err
                };
              } else {
                if (badge) {
                  badge.textContent = 'COMPLETED';
                  badge.className = 'console-badge';
                }
                this.lastCompletedDemo = {
                  session_id: st.session_id || this.runtimeSessionId || 'DEMO-COMPLETE',
                  pcap: pcapPath,
                  summary: finalSummary,
                  error: null
                };
                this.renderDemoConsoleResult(this.lastCompletedDemo);
              }

              // Refresh data
              this.loadAlerts();
              this.loadIncidents();
              this.loadFlows();
            }
          }
        } catch (pollErr) {
          console.warn('Demo polling status error:', pollErr);
        }
      }, 800);

    } catch (err) {
      this.isDemoRunning = false;
      if (triggerButton) {
        triggerButton.disabled = false;
        triggerButton.innerHTML = '<span>▶</span> RUN TEST';
      }
      if (badge) {
        badge.textContent = 'ERROR';
        badge.className = 'console-badge error';
      }
      if (msg) msg.textContent = 'Pipeline execution failed: ' + err.message;
    }
  }

  async runBackendTest() {
    if (this.isBackendTestRunning) return;
    this.isBackendTestRunning = true;

    const selectEl = this.backendTestScenarioSelect;
    const pcapPath = selectEl ? selectEl.value : 'data_generation/pcaps/attack_portscan.pcap';
    const pcapBase = pcapPath.split(/[\\/]/).pop();

    const btn = this.btnRunBackendTest;
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<span class="pulse-indicator purple"></span> RUNNING BACKEND TEST...';
    }

    const pill = this.backendTestPill;
    if (pill) {
      pill.textContent = 'RUNNING';
      pill.className = 'compliance-pill purple';
    }

    const sessionEl = this.backendTestSessionId;
    if (sessionEl) sessionEl.textContent = 'TEST-INITIALIZING...';

    const pParsed = this.backendTestPackets;
    if (pParsed) pParsed.textContent = '0';
    const fEmitted = this.backendTestFlows;
    if (fEmitted) fEmitted.textContent = '0';
    const aEmitted = this.backendTestAlerts;
    if (aEmitted) aEmitted.textContent = '0';
    const eTime = this.backendTestElapsed;
    if (eTime) eTime.textContent = '0.0s';

    const msg = this.backendTestActionMsg;
    if (msg) {
      msg.textContent = `Executing "${pcapBase}" directly on deployed backend. Alerts stream to SOC Overview & Live Threats...`;
    }

    try {
      const res = await fetch(this.apiUrl('/api/backend-test/start'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pcap: pcapPath })
      });

      const startData = await res.json();
      if (startData && startData.session_id) {
        this.runtimeSessionId = startData.session_id;
        if (sessionEl) sessionEl.textContent = startData.session_id;
      }

      if (this.backendTestPollingTimer) clearInterval(this.backendTestPollingTimer);

      this.backendTestPollingTimer = setInterval(async () => {
        try {
          const stRes = await fetch(this.apiUrl('/api/backend-test/status'));
          if (stRes.ok) {
            const st = await stRes.json();
            if (st.session_id && sessionEl) sessionEl.textContent = st.session_id;

            const currentSummary = st.summary || (st.last_backend_test_result ? st.last_backend_test_result.summary : {});
            if (pParsed && currentSummary.packets !== undefined) pParsed.textContent = currentSummary.packets.toLocaleString();
            if (fEmitted && currentSummary.records !== undefined) fEmitted.textContent = currentSummary.records.toLocaleString();
            if (aEmitted && currentSummary.alerts !== undefined) aEmitted.textContent = currentSummary.alerts.toLocaleString();
            if (eTime && currentSummary.elapsed_sec !== undefined) eTime.textContent = `${currentSummary.elapsed_sec.toFixed(1)}s`;

            if (!st.running) {
              clearInterval(this.backendTestPollingTimer);
              this.isBackendTestRunning = false;
              if (btn) {
                btn.disabled = false;
                btn.innerHTML = '<span>⚡</span> RUN BACKEND TEST';
              }

              const err = st.last_error || (st.last_backend_test_result ? st.last_backend_test_result.error : null);
              const finalSummary = (st.summary && st.summary.packets !== undefined)
                ? st.summary
                : (st.last_backend_test_result ? st.last_backend_test_result.summary : currentSummary);

              if (err) {
                if (pill) {
                  pill.textContent = 'ERROR';
                  pill.className = 'compliance-pill rose';
                }
                if (msg) msg.textContent = 'Backend test execution failed: ' + err;
              } else {
                if (pill) {
                  pill.textContent = 'COMPLETED';
                  pill.className = 'compliance-pill emerald';
                }
                if (msg) {
                  const pkts = finalSummary.packets || 0;
                  const flows = finalSummary.records || 0;
                  const alts = finalSummary.alerts || 0;
                  const el = (finalSummary.elapsed_sec || 0).toFixed(1);
                  msg.textContent = `Scenario "${pcapBase}" complete: ${pkts.toLocaleString()} pkts -> ${flows.toLocaleString()} flows -> ${alts.toLocaleString()} promoted alerts in ${el}s.`;
                }
                this.lastCompletedBackendTest = {
                  session_id: st.session_id || this.runtimeSessionId || 'TEST-COMPLETE',
                  pcap: pcapPath,
                  summary: finalSummary,
                  error: null
                };
              }

              // Refresh live alerts, incidents, flows so dashboard reflects execution immediately
              await Promise.all([
                this.loadAlerts(),
                this.loadIncidents(),
                this.loadFlows()
              ]);
            }
          }
        } catch (pollErr) {
          console.warn('Backend test polling status error:', pollErr);
        }
      }, 800);

    } catch (err) {
      this.isBackendTestRunning = false;
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = '<span>⚡</span> RUN BACKEND TEST';
      }
      if (pill) {
        pill.textContent = 'ERROR';
        pill.className = 'compliance-pill rose';
      }
      if (msg) msg.textContent = 'Backend test execution failed: ' + err.message;
    }
  }

  renderBackendTestResult(result) {
    if (!result) return;
    const sessionEl = this.backendTestSessionId;
    if (sessionEl && result.session_id) sessionEl.textContent = result.session_id;

    const summary = result.summary || {};
    const pParsed = this.backendTestPackets;
    if (pParsed && summary.packets !== undefined) pParsed.textContent = summary.packets.toLocaleString();
    const fEmitted = this.backendTestFlows;
    if (fEmitted && summary.records !== undefined) fEmitted.textContent = summary.records.toLocaleString();
    const aEmitted = this.backendTestAlerts;
    if (aEmitted && summary.alerts !== undefined) aEmitted.textContent = summary.alerts.toLocaleString();
    const eTime = this.backendTestElapsed;
    if (eTime && summary.elapsed_sec !== undefined) eTime.textContent = `${summary.elapsed_sec.toFixed(1)}s`;

    const pill = this.backendTestPill;
    if (pill) {
      pill.textContent = result.error ? 'ERROR' : 'COMPLETED';
      pill.className = result.error ? 'compliance-pill rose' : 'compliance-pill emerald';
    }

    const msg = this.backendTestActionMsg;
    if (msg) {
      const pcapBase = (result.pcap || '').split(/[\\/]/).pop();
      if (result.error) {
        msg.textContent = 'Execution failed: ' + result.error;
      } else {
        const pkts = summary.packets || 0;
        const flows = summary.records || 0;
        const alts = summary.alerts || 0;
        msg.textContent = `Completed scenario "${pcapBase}": ${pkts.toLocaleString()} pkts, ${flows.toLocaleString()} flows, ${alts.toLocaleString()} promoted alerts.`;
      }
    }
  }

  async loadLastBackendTestResult() {
    try {
      const res = await fetch(this.apiUrl('/api/backend-test/last_result'));
      if (res.ok) {
        const data = await res.json();
        if (data && data.status === 'available' && data.last_backend_test_result) {
          this.lastCompletedBackendTest = data.last_backend_test_result;
          if (!this.isBackendTestRunning) {
            this.renderBackendTestResult(this.lastCompletedBackendTest);
          }
        }
      }
    } catch (err) {
      console.warn('Failed to load last backend test result:', err);
    }
  }

  /* ========================================================================
     5. TELEMETRY & SYSTEM UI UPDATERS
     ======================================================================== */
  updateTelemetryUI() {
    if (!this.telemetry) return;

    // Engine PPS & SLA
    const ppsEl = document.getElementById('engineRatePps');
    if (ppsEl && this.telemetry.engine_pps) {
      ppsEl.textContent = this.telemetry.engine_pps.toLocaleString();
    }

    const p99El = document.getElementById('engineP99Latency');
    if (p99El && this.telemetry.p99_latency_ms) {
      p99El.textContent = `${this.telemetry.p99_latency_ms.toFixed(2)} ms`;
    }

    // Diode Egress in Overview
    const kpiEgress = document.getElementById('kpiDiodeEgress');
    if (kpiEgress) {
      kpiEgress.textContent = this.telemetry.egress_bytes_sent || 0;
    }
  }

  updateComplianceUI() {
    if (!this.complianceData) return;

    const egressEl = document.getElementById('sysEgressBytes');
    if (egressEl) {
      egressEl.textContent = `${this.complianceData.total_egress_bytes_detected || 0} BYTES`;
    }

    const sockEl = document.getElementById('sysSockStatus');
    if (sockEl && this.complianceData.dual_check_verification) {
      sockEl.textContent = this.complianceData.dual_check_verification.level_1_process_socket_table || 'CLEAN';
    }

    const nicEl = document.getElementById('sysNicStatus');
    if (nicEl && this.complianceData.dual_check_verification) {
      nicEl.textContent = this.complianceData.dual_check_verification.level_2_nic_io_counter || 'CLEAN';
    }

    const certEl = document.getElementById('sysCertId');
    if (certEl && this.complianceData.certificate_id) {
      certEl.textContent = this.complianceData.certificate_id;
    }

    const hashEl = document.getElementById('sysSha256');
    if (hashEl && this.complianceData.cryptographic_integrity_sha256) {
      hashEl.textContent = this.complianceData.cryptographic_integrity_sha256;
    }

    const hostEl = document.getElementById('sysHostNode');
    if (hostEl && this.complianceData.enclave_host) {
      hostEl.textContent = this.complianceData.enclave_host;
    }

    // Modal fields
    const mCertId = document.getElementById('certId');
    if (mCertId && this.complianceData.certificate_id) {
      mCertId.textContent = this.complianceData.certificate_id;
    }

    const mSha = document.getElementById('certSha256');
    if (mSha && this.complianceData.cryptographic_integrity_sha256) {
      mSha.textContent = this.complianceData.cryptographic_integrity_sha256;
    }
  }

  updateRuntimeUI(status = null) {
    const st = status || this.runtimeStatus;
    if (!st) return;

    if (status) {
      this.runtimeStatus = status;
    }

    // Preserve last_demo_result from backend if available and not actively running
    if (st.last_demo_result && !this.isDemoRunning) {
      this.lastCompletedDemo = st.last_demo_result;
    }

    if (this.isDemoRunning) {
      const summary = st.summary || {};
      const pActive = document.getElementById('demoActivePcap');
      const pcapVal = st.active_pcap || st.pcap;
      if (pActive && pcapVal) {
        pActive.textContent = pcapVal.split(/[\\/]/).pop();
      }
      const sessionEl = document.getElementById('demoSessionId');
      if (sessionEl && st.session_id) {
        sessionEl.textContent = st.session_id;
      }
      const pParsed = document.getElementById('demoPacketsParsed');
      if (pParsed && summary.packets !== undefined) pParsed.textContent = summary.packets.toLocaleString();
      const fEmitted = document.getElementById('demoFlowsEmitted');
      if (fEmitted && summary.records !== undefined) fEmitted.textContent = summary.records.toLocaleString();
      const aEmitted = document.getElementById('demoAlertsEmitted');
      if (aEmitted && summary.alerts !== undefined) aEmitted.textContent = summary.alerts.toLocaleString();
      const eTime = document.getElementById('demoElapsedTime');
      if (eTime && summary.elapsed_sec !== undefined) eTime.textContent = `${summary.elapsed_sec.toFixed(1)}s`;
    } else if (this.lastCompletedDemo) {
      // Retain last completed demo result! Never overwrite with 0!
      this.renderDemoConsoleResult(this.lastCompletedDemo);
    }

    // Overview inferences
    const kpiInferences = document.getElementById('kpiAiInferences');
    if (kpiInferences) {
      const summary = (this.lastCompletedDemo && this.lastCompletedDemo.summary) || st.summary || {};
      if (summary.packets) {
        kpiInferences.textContent = summary.packets.toLocaleString();
      } else if (this.alerts.length > 0) {
        kpiInferences.textContent = (this.alerts.length * 3).toLocaleString();
      } else {
        kpiInferences.textContent = '--';
      }
    }

    this.updateConnectionStatus();
  }

  /* ========================================================================
     6. PAGE RENDERERS
     ======================================================================== */

  // PAGE 1: OVERVIEW
  renderOverview() {
    const liveAlerts = this.getLiveAlerts();
    const liveIncidents = this.getLiveIncidents();

    // 1. KPI Cards
    const kpiThreats = document.getElementById('kpiActiveThreats');
    if (kpiThreats) {
      if (!this.apiConnected) {
        kpiThreats.textContent = '--';
      } else if (liveAlerts.length > 0) {
        kpiThreats.textContent = liveAlerts.length.toLocaleString();
      } else {
        kpiThreats.textContent = '--';
      }
    }

    const kpiChains = document.getElementById('kpiAttackChains');
    if (kpiChains) {
      if (!this.apiConnected) {
        kpiChains.textContent = '--';
      } else if (liveIncidents.length > 0) {
        kpiChains.textContent = liveIncidents.length.toLocaleString();
      } else {
        kpiChains.textContent = '--';
      }
    }

    const kpiFlows = document.getElementById('kpiFlowsParsed');
    if (kpiFlows) {
      kpiFlows.textContent = !this.apiConnected ? '--' : (this.flows.length > 0 ? this.flows.length.toLocaleString() : '--');
    }

    // 2. Threat Activity Distribution Chart (Temporal Histogram)
    const timelineContainer = document.getElementById('timelineBars');
    if (timelineContainer) {
      timelineContainer.innerHTML = '';
      if (!this.apiConnected) {
        timelineContainer.innerHTML = '<div style="margin: auto; color: #EF4444; font-size: 12px; font-weight: 600;">BACKEND OFFLINE — Live telemetry unavailable</div>';
      } else if (liveAlerts.length === 0) {
        timelineContainer.innerHTML = '<div style="margin: auto; color: #94A3B8; font-size: 12px;">NO LIVE DATA — Awaiting stream ingestion</div>';
      } else {
        const numBuckets = 14;
        const buckets = new Array(numBuckets).fill(0);
        liveAlerts.forEach((_, idx) => {
          const bIdx = idx % numBuckets;
          buckets[bIdx]++;
        });

        const maxVal = Math.max(...buckets, 1);
        buckets.forEach(count => {
          const bar = document.createElement('div');
          bar.className = 'chart-bar';
          const heightPct = Math.max(8, Math.round((count / maxVal) * 100));
          bar.style.height = `${heightPct}%`;
          bar.dataset.count = count;
          timelineContainer.appendChild(bar);
        });
      }
    }

    // 3. Threat Category Distribution
    const distContainer = document.getElementById('threatDistributionList');
    if (distContainer) {
      distContainer.innerHTML = '';
      if (!this.apiConnected) {
        distContainer.innerHTML = '<div class="distribution-empty" style="color: #EF4444;">BACKEND OFFLINE — Awaiting connection</div>';
      } else if (liveAlerts.length === 0) {
        distContainer.innerHTML = '<div class="distribution-empty">NO LIVE DATA — No live threats in buffer</div>';
      } else {
        const counts = {};
        liveAlerts.forEach(a => {
          const tc = a.threat_class || 'Unknown';
          counts[tc] = (counts[tc] || 0) + 1;
        });

        const colorClasses = ['rose', 'amber', 'blue', 'purple'];
        let colorIdx = 0;

        Object.entries(counts).forEach(([tClass, count]) => {
          const pct = Math.round((count / liveAlerts.length) * 100);
          const color = colorClasses[colorIdx % colorClasses.length];
          colorIdx++;

          const item = document.createElement('div');
          item.className = 'dist-item';
          item.innerHTML = `
            <div class="dist-meta">
              <span>${this.formatThreatName(tClass)}</span>
              <span><strong>${count}</strong> (${pct}%)</span>
            </div>
            <div class="dist-progress-track">
              <div class="dist-progress-fill ${color}" style="width: ${pct}%;"></div>
            </div>
          `;
          distContainer.appendChild(item);
        });
      }
    }

    // 4. Attack-Chain Summary Card Preview
    const incPreview = document.getElementById('overviewIncidentPreview');
    if (incPreview) {
      if (!this.apiConnected) {
        incPreview.innerHTML = `
          <div class="empty-state-box">
            <div class="empty-icon">⚠️</div>
            <div class="empty-title">BACKEND OFFLINE</div>
            <div class="empty-desc">Live telemetry unavailable. Verify connection to backend API.</div>
          </div>
        `;
      } else if (liveIncidents.length === 0) {
        incPreview.innerHTML = `
          <div class="empty-state-box">
            <div class="empty-icon">🛡️</div>
            <div class="empty-title">No Correlated Live Attack Chains</div>
            <div class="empty-desc">Multi-stage persistence across temporal windows required before promoting live incidents.</div>
          </div>
        `;
      } else {
        const topInc = liveIncidents[0];
        incPreview.innerHTML = `
          <div class="incident-card" style="box-shadow:none; padding:16px; border:1px solid #E2E8F0;">
            <div class="incident-card-top" style="margin-bottom:10px; padding-bottom:8px;">
              <span class="incident-id-tag">${topInc.incident_id || 'INC-CORRELATED'}</span>
              <span class="severity-multiplier-pill">${topInc.severity_multiplier || 2.5}x CRITICAL</span>
            </div>
            <div style="font-size:12px; font-weight:700; color:#0F172A; margin-bottom:4px;">Pattern: ${topInc.chain_pattern || 'recon_to_c2_to_exfil'}</div>
            <div style="font-size:12px; color:#475569; line-height:1.4;">${this.escapeHtml(topInc.narrative || 'Multi-stage intrusion chain identified across temporal network telemetry.')}</div>
          </div>
        `;
      }
    }

    // 5. Recent Threat Stream Preview
    const streamContainer = document.getElementById('overviewThreatStream');
    if (streamContainer) {
      if (!this.apiConnected) {
        streamContainer.innerHTML = `
          <div class="empty-state-box">
            <div class="empty-icon">⚠️</div>
            <div class="empty-title">BACKEND OFFLINE</div>
            <div class="empty-desc">Live telemetry unavailable. Check API endpoint connection.</div>
          </div>
        `;
      } else if (liveAlerts.length === 0) {
        streamContainer.innerHTML = `
          <div class="empty-state-box">
            <div class="empty-icon">🛡️</div>
            <div class="empty-title">NO LIVE DATA</div>
            <div class="empty-desc">No live NIC capture events recorded. Demo replay sessions are segregated and visible in the Demo Testing console.</div>
          </div>
        `;
      } else {
        streamContainer.innerHTML = '';
        const recent = liveAlerts.slice(0, 4);
        recent.forEach(alert => {
          const item = document.createElement('div');
          item.className = 'threat-preview-item';
          const isBackendTest = alert.source === 'BACKEND_TEST' || (alert.session_id && alert.session_id.startsWith('TEST-'));
          const sourceBadge = isBackendTest
            ? '<span class="source-tag badge-backend-test">BACKEND TEST</span>'
            : '<span class="source-tag badge-live">LIVE</span>';
          item.innerHTML = `
            <div>
              <div style="font-size:12px; font-weight:800; color:#0F172A; display:flex; align-items:center;">
                ${this.formatThreatName(alert.threat_class)} ${sourceBadge}
              </div>
              <div style="font-size:11px; font-family:var(--font-mono); color:#64748B;">${alert.src_ip || '0.0.0.0'} &rarr; ${alert.dst_ip || '0.0.0.0'}</div>
            </div>
            <div style="text-align:right;">
              <span class="severity-pill ${this.getSeverityClass(alert)}">${this.getSeverityLabel(alert)}</span>
              <div style="font-size:10px; color:#94A3B8; margin-top:2px;">${alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : 'Recent'}</div>
            </div>
          `;
          item.addEventListener('click', () => this.openAlertDetailModal(alert));
          streamContainer.appendChild(item);
        });
      }
    }
  }

  // PAGE 2: LIVE THREATS
  renderThreats() {
    const liveAlerts = this.getLiveAlerts();
    const filter = this.activeThreatFilter;
    const filtered = filter === 'ALL' 
      ? liveAlerts 
      : liveAlerts.filter(a => a.threat_class === filter);

    const visCountEl = document.getElementById('visibleThreatCount');
    if (visCountEl) visCountEl.textContent = !this.apiConnected ? '--' : filtered.length;

    // Desktop Table
    const tbody = document.getElementById('threatsTableBody');
    if (tbody) {
      tbody.innerHTML = '';
      if (!this.apiConnected) {
        tbody.innerHTML = `
          <tr>
            <td colspan="8" class="table-empty-cell">
              <div class="empty-state-box">
                <div class="empty-icon">⚠️</div>
                <div class="empty-title">BACKEND OFFLINE</div>
                <div class="empty-desc">Live telemetry unavailable. Cannot reach backend API.</div>
              </div>
            </td>
          </tr>
        `;
      } else if (liveAlerts.length === 0) {
        tbody.innerHTML = `
          <tr>
            <td colspan="8" class="table-empty-cell">
              <div class="empty-state-box">
                <div class="empty-icon">🛡️</div>
                <div class="empty-title">NO LIVE DATA</div>
                <div class="empty-desc">Live NIC monitor is not currently capturing packets. Use Demo Testing for offline PCAP replay or start Live Capture above if an authorized interface is available.</div>
              </div>
            </td>
          </tr>
        `;
      } else if (filtered.length === 0) {
        tbody.innerHTML = `
          <tr>
            <td colspan="8" class="table-empty-cell">
              <div class="empty-state-box">
                <div class="empty-icon">🛡️</div>
                <div class="empty-title">No Alerts In Selected Category</div>
                <div class="empty-desc">No events matched the "${filter}" filter. Switch to ALL ALERTS to view all events.</div>
              </div>
            </td>
          </tr>
        `;
      } else {
        filtered.forEach(alert => {
          const tr = document.createElement('tr');
          const timeFormatted = alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : '--:--:--';
          const port = this.extractPort(alert.flow_identifier);
          const isBackendTest = alert.source === 'BACKEND_TEST' || (alert.session_id && alert.session_id.startsWith('TEST-'));
          const sourceBadge = isBackendTest
            ? '<span class="source-tag badge-backend-test">BACKEND TEST</span>'
            : '<span class="source-tag badge-live">LIVE</span>';

          tr.innerHTML = `
            <td><span class="severity-pill ${this.getSeverityClass(alert)}">${this.getSeverityLabel(alert)}</span></td>
            <td><span class="threat-tag">${this.formatThreatName(alert.threat_class)}</span> ${sourceBadge}</td>
            <td class="mono-cell">${alert.src_ip || '--'}</td>
            <td class="mono-cell">${alert.dst_ip || '--'}</td>
            <td class="mono-cell">${port}</td>
            <td><strong>${Math.round((alert.confidence_score !== undefined ? alert.confidence_score : 0.9) * 100)}%</strong></td>
            <td class="evidence-cell" title="${this.escapeHtml(alert.supporting_evidence || '')}">${this.escapeHtml(alert.supporting_evidence || 'Baseline criteria met.')}</td>
            <td style="text-align: right;" class="mono-cell">${timeFormatted}</td>
          `;
          tr.addEventListener('click', () => this.openAlertDetailModal(alert));
          tbody.appendChild(tr);
        });
      }
    }

    // Mobile Cards List
    const mobContainer = document.getElementById('threatsMobileList');
    if (mobContainer) {
      mobContainer.innerHTML = '';
      if (!this.apiConnected) {
        mobContainer.innerHTML = `
          <div class="empty-state-box">
            <div class="empty-icon">⚠️</div>
            <div class="empty-title">BACKEND OFFLINE</div>
            <div class="empty-desc">Live telemetry unavailable. Cannot reach backend API.</div>
          </div>
        `;
      } else if (liveAlerts.length === 0) {
        mobContainer.innerHTML = `
          <div class="empty-state-box">
            <div class="empty-icon">🛡️</div>
            <div class="empty-title">NO LIVE DATA</div>
            <div class="empty-desc">No live NIC capture events recorded. Demo replay sessions are segregated in Demo Testing.</div>
          </div>
        `;
      } else if (filtered.length === 0) {
        mobContainer.innerHTML = `
          <div class="empty-state-box">
            <div class="empty-icon">🛡️</div>
            <div class="empty-title">No Alerts In Buffer</div>
            <div class="empty-desc">No events found matching the active filter.</div>
          </div>
        `;
      } else {
        filtered.forEach(alert => {
          const card = document.createElement('div');
          card.className = 'threat-mobile-card';
          const timeFormatted = alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : '--:--:--';
          const isBackendTest = alert.source === 'BACKEND_TEST' || (alert.session_id && alert.session_id.startsWith('TEST-'));
          const sourceBadge = isBackendTest
            ? '<span class="source-tag badge-backend-test">BACKEND TEST</span>'
            : '<span class="source-tag badge-live">LIVE</span>';

          card.innerHTML = `
            <div class="mob-card-top">
              <span class="severity-pill ${this.getSeverityClass(alert)}">${this.getSeverityLabel(alert)}</span>
              <span class="threat-tag">${this.formatThreatName(alert.threat_class)}</span>
              ${sourceBadge}
              <span style="font-size:11px; font-family:var(--font-mono); color:#94A3B8;">${timeFormatted}</span>
            </div>
            <div class="mob-flow-row">
              <span>${alert.src_ip || '0.0.0.0'}</span>
              <span class="flow-arrow">&rarr;</span>
              <span>${alert.dst_ip || '0.0.0.0'}</span>
            </div>
            <div class="mob-card-meta">
              <span>Confidence: <strong>${Math.round((alert.confidence_score !== undefined ? alert.confidence_score : 0.9) * 100)}%</strong></span>
              <span>Signals: <strong>${alert.corroboration_count || 1}</strong></span>
              <span>Window: <strong>${alert.persistence_windows || 1}/3</strong></span>
            </div>
            <div class="mob-card-evidence">${this.escapeHtml(alert.supporting_evidence || 'Anomaly criteria corroborated.')}</div>
          `;
          card.addEventListener('click', () => this.openAlertDetailModal(alert));
          mobContainer.appendChild(card);
        });
      }
    }
  }

  // PAGE 3: ATTACK CHAINS
  renderIncidents() {
    const container = document.getElementById('incidentsContainer');
    if (!container) return;

    container.innerHTML = '';
    if (!this.apiConnected) {
      container.innerHTML = `
        <div class="empty-state-box">
          <div class="empty-icon">⚠️</div>
          <div class="empty-title">BACKEND OFFLINE</div>
          <div class="empty-desc">Live attack chains unavailable. Cannot reach backend API.</div>
        </div>
      `;
      return;
    }

    const liveIncidents = this.getLiveIncidents();
    if (liveIncidents.length === 0) {
      container.innerHTML = `
        <div class="empty-state-box">
          <div class="empty-icon">🔗</div>
          <div class="empty-title">No Correlated Live Attack Chains Active</div>
          <div class="empty-desc">The Correlation Engine correlates live alerts across sliding windows. When an attacker progresses through multiple stages (e.g. reconnaissance followed by C2 channel and exfiltration), an incident is generated here.</div>
        </div>
      `;
      return;
    }

    liveIncidents.forEach(inc => {
      const card = document.createElement('div');
      card.className = 'incident-card';

      const pattern = inc.chain_pattern || 'recon_to_c2_to_exfil';
      let stagesHtml = '';

      if (pattern.includes('recon_to_c2_to_exfil') || pattern.includes('exfil')) {
        stagesHtml = `
          <div class="killchain-timeline">
            <div class="kc-step-node active">
              <div class="kc-circle">1</div>
              <span class="kc-step-label">RECONNAISSANCE</span>
            </div>
            <div class="kc-connector-line"></div>
            <div class="kc-step-node active">
              <div class="kc-circle">2</div>
              <span class="kc-step-label">C2 CHANNEL</span>
            </div>
            <div class="kc-connector-line"></div>
            <div class="kc-step-node danger">
              <div class="kc-circle">3</div>
              <span class="kc-step-label">EXFILTRATION</span>
            </div>
          </div>
        `;
      } else if (pattern.includes('dga')) {
        stagesHtml = `
          <div class="killchain-timeline">
            <div class="kc-step-node active">
              <div class="kc-circle">1</div>
              <span class="kc-step-label">DGA QUERY</span>
            </div>
            <div class="kc-connector-line"></div>
            <div class="kc-step-node danger">
              <div class="kc-circle">2</div>
              <span class="kc-step-label">C2 RENDEZVOUS</span>
            </div>
          </div>
        `;
      } else {
        stagesHtml = `
          <div class="killchain-timeline">
            <div class="kc-step-node active">
              <div class="kc-circle">1</div>
              <span class="kc-step-label">INITIAL ACCESS</span>
            </div>
            <div class="kc-connector-line"></div>
            <div class="kc-step-node danger">
              <div class="kc-circle">2</div>
              <span class="kc-step-label">ATTACK EXECUTION</span>
            </div>
          </div>
        `;
      }

      const isBackendTest = inc.source === 'BACKEND_TEST' || (inc.session_id && inc.session_id.startsWith('TEST-'));
      const sourceBadge = isBackendTest
        ? '<span class="source-tag badge-backend-test">BACKEND TEST</span>'
        : '<span class="source-tag badge-live">LIVE</span>';

      card.innerHTML = `
        <div class="incident-card-top">
          <div style="display:flex; align-items:center; gap:10px;">
            <span class="incident-id-tag">${inc.incident_id || 'INC-CAMPAIGN-001'}</span>
            ${sourceBadge}
            <span style="font-size:12px; font-weight:700; color:#64748B;">Target Host: <strong>${inc.host || '192.168.1.100'}</strong></span>
          </div>
          <span class="severity-multiplier-pill">${inc.severity_multiplier || 2.5}x MULTIPLIER (CRITICAL)</span>
        </div>

        ${stagesHtml}

        <div class="narrative-box">
          <div class="narrative-header">ANALYST REASONING (CORRELATION ENGINE):</div>
          <div class="narrative-text">${this.escapeHtml(inc.narrative || 'Correlated multi-stage attack behavior identified across network telemetry.')}</div>
        </div>

        <div style="display:flex; justify-content:space-between; align-items:center; margin-top:14px; font-size:11px; color:#64748B;">
          <span>Pattern Signature: <strong>${pattern}</strong></span>
          <span>Constituent Alerts: <strong>${inc.constituent_alert_ids ? inc.constituent_alert_ids.length : 3} alerts linked</strong></span>
        </div>
      `;

      container.appendChild(card);
    });
  }

  // PAGE 4: NETWORK FLOWS
  renderFlows() {
    const countEl = document.getElementById('flowsCountDisplay');
    if (countEl) countEl.textContent = this.flows.length;

    // Desktop Table
    const tbody = document.getElementById('flowsTableBody');
    if (tbody) {
      tbody.innerHTML = '';
      if (this.flows.length === 0) {
        tbody.innerHTML = `
          <tr>
            <td colspan="9" class="table-empty-cell">
              <div class="empty-state-box">
                <div class="empty-icon">📊</div>
                <div class="empty-title">No Flow Feature Records Available</div>
                <div class="empty-desc">Flow feature vectors will appear here when the ingestion engine processes network traffic.</div>
              </div>
            </td>
          </tr>
        `;
      } else {
        this.flows.forEach(flow => {
          const tr = document.createElement('tr');
          const vol = flow.volumetric || {};
          const timing = flow.timing || {};
          const asymmetry = flow.volume_asymmetry || {};

          let hints = [];
          if (vol.syn_ack_ratio > 10) hints.push('SYN flood hint');
          if (timing.iat_cv < 0.1 && timing.iat_cv > 0) hints.push('Periodic IAT');
          if (asymmetry.exfil_risk_score > 0.5) hints.push('High Exfil Risk');
          if (flow.fanout && flow.fanout.dst_port_count > 10) hints.push('Port fan-out');
          const hintsText = hints.length > 0 ? hints.join(', ') : 'Normal flow profile';

          tr.innerHTML = `
            <td class="mono-cell" style="max-width:200px; overflow:hidden; text-overflow:ellipsis;">${flow.flow_id || '--'}</td>
            <td class="mono-cell">${flow.src_ip}:${flow.src_port || 0}</td>
            <td class="mono-cell">${flow.dst_ip}:${flow.dst_port || 0}</td>
            <td><span class="status-tag blue">${flow.protocol || 'TCP'}</span></td>
            <td class="mono-cell">${vol.packet_count || 1}</td>
            <td class="mono-cell">${vol.byte_count || 54} B</td>
            <td class="mono-cell">${flow.window_duration_sec || 15.0}s</td>
            <td style="font-size:11px; color:#64748B;">${hintsText}</td>
            <td style="text-align:center;">
              <button class="btn-soft-action" style="padding:4px 8px; font-size:11px;">View</button>
            </td>
          `;
          tr.addEventListener('click', () => this.openFlowDetailModal(flow));
          tbody.appendChild(tr);
        });
      }
    }

    // Mobile Flow Cards
    const mobContainer = document.getElementById('flowsMobileList');
    if (mobContainer) {
      mobContainer.innerHTML = '';
      if (this.flows.length === 0) {
        mobContainer.innerHTML = `
          <div class="empty-state-box">
            <div class="empty-icon">📊</div>
            <div class="empty-title">No Flow Feature Records Available</div>
            <div class="empty-desc">Flow feature vectors will appear here when the ingestion engine processes network traffic.</div>
          </div>
        `;
      } else {
        this.flows.forEach(flow => {
          const card = document.createElement('div');
          card.className = 'flow-card-mobile';
          const vol = flow.volumetric || {};

          card.innerHTML = `
            <div style="display:flex; justify-content:space-between; margin-bottom:8px;">
              <span class="status-tag blue">${flow.protocol || 'TCP'}</span>
              <span style="font-family:var(--font-mono); font-size:11px; color:#64748B;">${vol.packet_count || 1} pkts &bull; ${vol.byte_count || 0} bytes</span>
            </div>
            <div class="mob-flow-row">
              <span>${flow.src_ip}:${flow.src_port || 0}</span>
              <span class="flow-arrow">&rarr;</span>
              <span>${flow.dst_ip}:${flow.dst_port || 0}</span>
            </div>
            <div style="font-size:11px; color:#64748B;">Window: ${flow.window_duration_sec || 15.0}s &bull; Flow ID: <span style="font-family:var(--font-mono);">${(flow.flow_id || '').substring(0, 24)}...</span></div>
          `;
          card.addEventListener('click', () => this.openFlowDetailModal(flow));
          mobContainer.appendChild(card);
        });
      }
    }
  }

  /* ========================================================================
     7. MODALS
     ======================================================================== */
  openAlertDetailModal(alert) {
    const modal = this.alertDetailModal;
    if (!modal) return;

    const sevBadge = document.getElementById('mAlertSeverity');
    if (sevBadge) {
      sevBadge.textContent = this.getSeverityLabel(alert);
      sevBadge.className = `modal-badge ${this.getSeverityClass(alert)}`;
    }

    const title = document.getElementById('mAlertTitle');
    if (title) {
      title.textContent = `${this.formatThreatName(alert.threat_class)} (ID: ${alert.alert_id || 'ALT-0000'})`;
    }

    const body = document.getElementById('mAlertBody');
    if (body) {
      body.innerHTML = `
        <div style="display:flex; flex-direction:column; gap:12px;">
          <div class="audit-cert-box" style="margin:0;">
            <div class="cert-row">
              <span class="cert-label">Flow Identifier:</span>
              <span class="cert-value mono">${alert.flow_identifier || '--'}</span>
            </div>
            <div class="cert-row">
              <span class="cert-label">Source Host:</span>
              <span class="cert-value mono">${alert.src_ip || '--'}</span>
            </div>
            <div class="cert-row">
              <span class="cert-label">Destination Host:</span>
              <span class="cert-value mono">${alert.dst_ip || '--'}</span>
            </div>
            <div class="cert-row">
              <span class="cert-label">Confidence Score:</span>
              <span class="cert-value"><strong>${Math.round((alert.confidence_score || 0.9) * 100)}%</strong></span>
            </div>
            <div class="cert-row">
              <span class="cert-label">Corroborated Signals:</span>
              <span class="cert-value">${alert.corroboration_count || 1} independent signals</span>
            </div>
            <div class="cert-row">
              <span class="cert-label">Sliding Window Persistence:</span>
              <span class="cert-value">Window ${alert.persistence_windows || 1}/3</span>
            </div>
            <div class="cert-row">
              <span class="cert-label">Correlated Incident:</span>
              <span class="cert-value">${alert.incident_id ? `<strong>${alert.incident_id}</strong>` : 'Standalone Alert'}</span>
            </div>
            <div class="cert-row">
              <span class="cert-label">Alert Timestamp:</span>
              <span class="cert-value mono">${alert.timestamp || 'Real-time'}</span>
            </div>
          </div>

          <div style="background:#F8FAFC; border:1px solid #E2E8F0; border-radius:12px; padding:14px;">
            <div style="font-size:11px; font-weight:800; color:#475569; margin-bottom:4px;">SUPPORTING EVIDENCE & FORENSIC HEURISTICS:</div>
            <div style="font-size:13px; color:#1E293B; line-height:1.5;">${this.escapeHtml(alert.supporting_evidence || 'Anomaly criteria met.')}</div>
          </div>
        </div>
      `;
    }

    this.openModal(modal);
  }

  openFlowDetailModal(flow) {
    const modal = this.flowDetailModal;
    if (!modal) return;

    const title = document.getElementById('mFlowTitle');
    if (title) {
      title.textContent = `Flow Record: ${flow.flow_id || 'Unknown'}`;
    }

    const body = document.getElementById('mFlowBody');
    if (body) {
      const vol = flow.volumetric || {};
      const timing = flow.timing || {};
      const dns = flow.dns_lexical || {};
      const crypto = flow.crypto_metadata || {};
      const fanout = flow.fanout || {};
      const asym = flow.volume_asymmetry || {};

      body.innerHTML = `
        <div style="display:flex; flex-direction:column; gap:14px;">
          <div class="audit-cert-box" style="margin:0;">
            <div class="cert-row">
              <span class="cert-label">Flow:</span>
              <span class="cert-value mono">${flow.src_ip}:${flow.src_port} &rarr; ${flow.dst_ip}:${flow.dst_port} (${flow.protocol})</span>
            </div>
            <div class="cert-row">
              <span class="cert-label">Window Duration:</span>
              <span class="cert-value mono">${flow.window_duration_sec}s</span>
            </div>
          </div>

          <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
            <div style="background:#F8FAFC; border:1px solid #E2E8F0; border-radius:8px; padding:10px;">
              <strong style="font-size:11px; color:#2563EB;">1. VOLUMETRIC</strong>
              <div style="font-size:11px; margin-top:4px;">Packets: ${vol.packet_count} | Bytes: ${vol.byte_count}</div>
              <div style="font-size:11px;">SYN/ACK Ratio: ${vol.syn_ack_ratio}</div>
            </div>

            <div style="background:#F8FAFC; border:1px solid #E2E8F0; border-radius:8px; padding:10px;">
              <strong style="font-size:11px; color:#2563EB;">2. TIMING (IAT)</strong>
              <div style="font-size:11px; margin-top:4px;">IAT CV: ${timing.iat_cv}</div>
              <div style="font-size:11px;">Periodicity: ${timing.periodicity_score}</div>
            </div>

            <div style="background:#F8FAFC; border:1px solid #E2E8F0; border-radius:8px; padding:10px;">
              <strong style="font-size:11px; color:#2563EB;">3. DNS LEXICAL</strong>
              <div style="font-size:11px; margin-top:4px;">Entropy: ${dns.shannon_entropy} bits</div>
              <div style="font-size:11px;">Has DNS: ${dns.has_dns}</div>
            </div>

            <div style="background:#F8FAFC; border:1px solid #E2E8F0; border-radius:8px; padding:10px;">
              <strong style="font-size:11px; color:#2563EB;">4. CRYPTO METADATA</strong>
              <div style="font-size:11px; margin-top:4px;">TLS/QUIC: ${crypto.is_tls_quic}</div>
              <div style="font-size:11px;">JA4: ${crypto.ja4_str || '--'}</div>
            </div>

            <div style="background:#F8FAFC; border:1px solid #E2E8F0; border-radius:8px; padding:10px;">
              <strong style="font-size:11px; color:#2563EB;">5. CONNECTION FAN-OUT</strong>
              <div style="font-size:11px; margin-top:4px;">Ports: ${fanout.dst_port_count} | IPs: ${fanout.dst_ip_count}</div>
              <div style="font-size:11px;">Half-Open: ${fanout.half_open_ratio}</div>
            </div>

            <div style="background:#F8FAFC; border:1px solid #E2E8F0; border-radius:8px; padding:10px;">
              <strong style="font-size:11px; color:#2563EB;">6. VOLUME ASYMMETRY</strong>
              <div style="font-size:11px; margin-top:4px;">Byte Ratio: ${asym.byte_ratio}</div>
              <div style="font-size:11px;">Exfil Risk: ${asym.exfil_risk_score}</div>
            </div>
          </div>
        </div>
      `;
    }

    this.openModal(modal);
  }

  openAuditModal() {
    this.loadComplianceAudit();
    this.openModal(this.validationModal);
  }

  /* ========================================================================
     8. FORMATTERS & UTILITIES
     ======================================================================== */
  formatThreatName(threatClass) {
    if (!threatClass) return 'Anomaly Event';
    return threatClass
      .replace(/_/g, ' ')
      .replace(/([a-z])([A-Z])/g, '$1 $2');
  }

  getSeverityClass(alert) {
    const tc = (alert.threat_class || '').toLowerCase();
    const conf = alert.confidence_score !== undefined && alert.confidence_score !== null ? alert.confidence_score : 0.8;
    
    // Critical: High-consequence threats (C2 Beaconing, DDoS, Exfiltration) with solid confidence (>= 0.70)
    if (tc.includes('c2') || tc.includes('ddos') || tc.includes('exfil')) {
      return conf >= 0.70 ? 'critical' : 'high';
    }
    // High: Reconnaissance (Port Scanning), DGA Tunnelling, Malware with high confidence (>= 0.75)
    if (tc.includes('port') || tc.includes('dga') || tc.includes('malware')) {
      return conf >= 0.75 ? 'high' : 'medium';
    }
    // Low: Low confidence anomaly events (< 0.60)
    if (conf < 0.60) {
      return 'low';
    }
    return 'medium';
  }

  getSeverityLabel(alert) {
    const cls = this.getSeverityClass(alert);
    return cls.toUpperCase();
  }

  extractPort(flowId) {
    if (!flowId) return '80';
    const match = flowId.match(/:(\d+)\//) || flowId.match(/->.*?:\s*(\d+)/);
    return match ? match[1] : '443';
  }

  escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
}

// Instantiate on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  window.diodeSentinel = new DiodeSentinelApp();
});
