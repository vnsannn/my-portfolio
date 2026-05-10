import { firebaseApp }                             from "./firebase-config.js";
import { getAuth, onAuthStateChanged, signOut }    from "https://www.gstatic.com/firebasejs/11.7.1/firebase-auth.js";
import { getFirestore, doc, getDoc,
         updateDoc, arrayUnion, arrayRemove }       from "https://www.gstatic.com/firebasejs/11.7.1/firebase-firestore.js";

// ── FIREBASE INIT (uses shared firebase-config.js) ────────────

const _dAuth = getAuth(firebaseApp);
const _dDb   = getFirestore(firebaseApp);

// ── DATA ─────────────────────────────────────────────────────

const LEVEL_DATA = [
    { level: 'Exposure',    color: '#6b7280', desc: "Seen it, read about it, maybe ran someone else's code. Haven't written anything independently." },
    { level: 'Familiar',    color: '#f59e0b', desc: 'Can write basic things independently. Understands the fundamentals but has clear gaps. Needs reference for anything beyond basics.' },
    { level: 'Comfortable', color: '#10b981', desc: 'Builds real things with it. Understands how and why things work, not just copying patterns. Still has a ceiling but can problem-solve within that ceiling.' },
    { level: 'Proficient',  color: '#3b82f6', desc: 'Confident across most use cases. Writes clean, intentional code. Knows best practices and applies them. Gaps exist but they are specific and narrow.' },
    { level: 'Advanced',    color: '#8b5cf6', desc: 'Deep knowledge including internals, edge cases, and patterns. Can mentor others. Knows what they do not know and knows how to find it.' },
    { level: 'Expert',      color: '#ec4899', desc: 'Mastery. Contributes to the language or ecosystem itself, or is a go-to authority in professional settings. Rare.' },
];

// ── HTML SANITIZE HELPER ─────────────────────────────────────
// Guards against XSS from Firestore-sourced strings injected via innerHTML.
// Since only Vien writes to Firestore this is self-XSS only, but good practice.
function sanitize(str) {
    return String(str || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// ── URL SAFETY HELPER (S-04) ──────────────────────────────────
// Used before injecting any URL into an href attribute.
// Rejects javascript:, data:, and any other non-https scheme.
// Returns true only for strings that start with https://.
function isSafeUrl(url) {
    return typeof url === 'string' && url.startsWith('https://');
}

// ── FETCHED DATA STORES ───────────────────────────────────────

let FETCHED_PROJECTS   = []; // INFO.json objects from repo entries in timestamp.json
let FETCHED_TIMELINE   = []; // Direct timeline entries from timestamp.json
let FETCHED_CERTS      = []; // Entries from certs.json
let FETCHED_LANGS      = []; // Language metadata from portfolio/lang
let FETCHED_ABOUT      = { bio: {}, education: [], proficiency: [] }; // from portfolio/about
let FETCHED_MILESTONES = []; // type:'milestone' entries from portfolio/timestamp

// ── EMAILJS CREDENTIALS ───────────────────────────────────────

let EMAILJS_SERVICE_ID  = null;
let EMAILJS_TEMPLATE_ID = null;
let EMAILJS_PUBLIC_KEY  = null;

// ── GITHUB CREDENTIALS ────────────────────────────────────────
// GH_TOKEN is only populated after isEditor is confirmed (see auth-gated startup).
// It is never set for visitor sessions.

let GH_TOKEN = null;
let GH_OWNER = null;
let GH_REPO  = null;

// ── CREDENTIALS CACHE ─────────────────────────────────────────
// verifyEditorAccess() reads portfolio/credentials once and caches it here.
// loadAllData() then uses this cache — no second Firestore read needed.
// Cleared after all fields are extracted so the raw object doesn't linger.
let _credentialsCache = null;

// ── LOAD ALL DATA ─────────────────────────────────────────────

async function loadAllData() {

    // 1. timestamp
    try {
        const snap    = await getDoc(doc(_dDb, "portfolio", "timestamp"));
        if (snap.exists()) {
            const entries = snap.data().data || [];

            const repoEntries    = entries.filter(e => e.repo);
            const directEntries  = entries.filter(e => !e.repo);

            // Direct timeline entries (non-milestone)
            FETCHED_TIMELINE   = directEntries.filter(e => e.type !== 'milestone');
            // Milestone entries live in the same doc under type:'milestone'
            FETCHED_MILESTONES = directEntries.filter(e => e.type === 'milestone');

            // Repo entries
            const results = await Promise.all(
                repoEntries.map(e =>
                    fetch(`https://raw.githubusercontent.com/${e.repo}/main/INFO.json?t=${Date.now()}`)
                        .then(r => r.ok ? r.json() : null)
                        .catch(() => null)
                        .then(data => data ? { ...data, _repo: e.repo, date: e.date || null } : null)
                )
            );
            FETCHED_PROJECTS = results.filter(Boolean);
        }
    } catch {}

    // 2. Certs
    try {
        const snap = await getDoc(doc(_dDb, "portfolio", "certs"));
        if (snap.exists()) {
            const raw = snap.data().data;
            FETCHED_CERTS = Array.isArray(raw) ? raw : (raw?.certificates || []);
        }
    } catch {}

    // 3. EmailJS credentials — sourced from _credentialsCache set by verifyEditorAccess().
    // GitHub credentials (GH_TOKEN etc.) are NOT loaded here — they are set in the
    // auth-gated startup only after isEditor is confirmed. This prevents GH_TOKEN
    // from ever reaching visitor sessions (fixes S-01 / S-03).
    try {
        const json = _credentialsCache || {};
        EMAILJS_SERVICE_ID  = json.emailjs?.serviceId  || null;
        EMAILJS_TEMPLATE_ID = json.emailjs?.templateId || null;
        EMAILJS_PUBLIC_KEY  = json.emailjs?.publicKey  || null;
    } catch {}

    // 4. Language metadata
    try {
        const snap = await getDoc(doc(_dDb, "portfolio", "lang"));
        if (snap.exists()) {
            FETCHED_LANGS = snap.data().data || [];
        }
    } catch {}

    // 5. About data
    try {
        const snap = await getDoc(doc(_dDb, "portfolio", "about"));
        if (snap.exists()) {
            const d = snap.data();
            FETCHED_ABOUT = {
                bio:         d.bio         || {},
                education:   d.education   || [],
                proficiency: d.proficiency || [],
            };
        }
    } catch {}
}

// Credentials are read once in verifyEditorAccess() and cached in _credentialsCache.
// EmailJS fields are extracted in loadAllData(). GitHub fields are extracted in the
// auth-gated startup — only after isEditor is confirmed. See S-01 / S-03 fix.

// ── INIT ─────────────────────────────────────────────────────

const params         = new URLSearchParams(window.location.search);
const _editRequested = params.get('ref') === 'edit';
let   isEditor       = false;
let   isEditMode     = false;

const badge    = document.getElementById('modeBadge');
const header   = document.getElementById('dashHeader');
// content (dashContent) removed — was grabbed but never used
const navLinks = document.querySelectorAll('.nav-link');
const sections = document.querySelectorAll('.dash-section');

function initBadge() {
    if (badge) {
        badge.innerHTML = `${isEditor ? 'ADMIN' : 'VISITOR'} <i class="fa-solid fa-chevron-down badge-chevron"></i>`;
        if (isEditor) badge.classList.add('admin');
    }
}

// ── AUTH GATE ─────────────────────────────────────────────────
// S-02 fix: auth state is resolved FIRST. Firestore is only read once a live
// Firebase session is confirmed — making the credentials read authenticated.
// Firestore rules must enforce request.auth != null on portfolio/credentials.

async function verifyEditorAccess() {
    // Step 1: Resolve current Firebase auth state without touching Firestore.
    // Visitors with no session bail here — Firestore is never called for them.
    const user = await new Promise((resolve) => {
        const unsub = onAuthStateChanged(_dAuth, (u) => { unsub(); resolve(u); });
    });

    if (!user) return false;

    // Step 2: User has a live Firebase session — read credentials now.
    // The request is authenticated, so Firestore rules can enforce auth safely.
    try {
        const snap = await getDoc(doc(_dDb, "portfolio", "credentials"));
        if (!snap.exists()) return false;
        const json = snap.data().data || {};

        // Cache for loadAllData() (EmailJS) and the IIFE below (GitHub) — S-03 fix.
        _credentialsCache = json;

        const _allowed          = json.auth?.allowed    || null;
        const _allowedUidEmail  = json.auth?.uid_email  || null;
        const _allowedUidGoogle = json.auth?.uid_google || null;

        if (!_allowed || (!_allowedUidEmail && !_allowedUidGoogle)) return false;

        const isGoogleUid = user.uid === _allowedUidGoogle;
        const isEmailUid  = user.uid === _allowedUidEmail && user.email === _allowed;
        return isGoogleUid || isEmailUid;
    } catch {
        return false;
    }
}

// ── PDF.js WORKER CONFIG ──────────────────────────────────────

if (window.pdfjsLib) {
    pdfjsLib.GlobalWorkerOptions.workerSrc =
        'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
}

const SECTION_ORDER = ['home', 'about', 'timeline', 'projects', 'certificates', 'reach'];
let currentSection = 'home';
let skillsAnimated = false;

// ── SECTION SWITCHING ─────────────────────────────────────────

function switchSection(id) {
    if (id === currentSection) return;

    const current = document.getElementById('section-' + currentSection);
    const target  = document.getElementById('section-' + id);
    if (!target) return;

    if (current) current.classList.remove('active');

    target.classList.add('active');

    const innerScroll = target.querySelector('.section-with-profile');
    if (innerScroll) {
        innerScroll.scrollTop = 0;
    } else {
        target.scrollTop = 0;
    }

    currentSection = id;

    navLinks.forEach(link => {
        link.classList.toggle('active', link.dataset.section === id);
    });
    showHeader();

    if (id === 'about' && !skillsAnimated) {
        setTimeout(() => {
            const barsEl = document.getElementById('skillsBars');
            if (barsEl) barsEl.classList.add('animated');
            skillsAnimated = true;
        }, 350);
    }

    updateAboutEditBtnVisibility();
}

navLinks.forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        switchSection(link.dataset.section);
    });
});

// ── HEADER HIDE/SHOW ──────────────────────────────────────────

let headerVisible = true;
// ticking removed — only used in the commented-out RAF block

function showHeader() {
    if (!headerVisible) {
        header.classList.remove('hidden');
        headerVisible = true;
    }
}

// Per-section scroll state
const sectionScrollY  = new Map();
const scrollbarTimers = new Map();

function attachScrollListener(el) {
    sectionScrollY.set(el, 0);

    el.addEventListener('scroll', () => {
        const scrollY = el.scrollTop;
        el.classList.add('scrolling');
        clearTimeout(scrollbarTimers.get(el));
        scrollbarTimers.set(el, setTimeout(() => {
            el.classList.remove('scrolling');
        }, 1500));

        // Header hide/show — uncomment to re-enable
        // Note: I have this kind of personal preferences that I easily get bored on what I see so sometimes
        // I keep some block of codes commented instead of erasing so I can turn it on or off.
        /*
        if (!ticking) {
            window.requestAnimationFrame(() => {
                const lastY = sectionScrollY.get(el);
                if (scrollY > lastY && scrollY > 60) hideHeader();
                else if (scrollY < lastY) showHeader();
                sectionScrollY.set(el, scrollY);
                ticking = false;
            });
            ticking = true;
        }
        */
    });
}

sections.forEach(section => attachScrollListener(section));
document.querySelectorAll('.section-with-profile').forEach(el => attachScrollListener(el));

// ── SECTION-HIJACK SCROLL ─────────────────────────────────────
// U-02: requires two consecutive at-boundary wheel events in the same direction
// before switching sections, preventing accidental jumps during slow/careful scrolling.

let hijackCooldown = false;
let _hijackPrimed  = false;  // U-02: true after the first at-boundary event
let _hijackPrimedDir = 0;    // U-02: direction of the primed event (1 or -1)

function getAdjacentSection(dir) {
    const idx  = SECTION_ORDER.indexOf(currentSection);
    const next = idx + dir;
    if (next < 0 || next >= SECTION_ORDER.length) return null;
    return SECTION_ORDER[next];
}

function tryHijack(dir) {
    if (hijackCooldown) return;
    // U-02: only switch if the same direction was primed on the previous event
    if (_hijackPrimed && _hijackPrimedDir === dir) {
        _hijackPrimed = false;
        _hijackPrimedDir = 0;
        const target = getAdjacentSection(dir);
        if (!target) return;
        hijackCooldown = true;
        switchSection(target);
        setTimeout(() => { hijackCooldown = false; }, 300);
    } else {
        // Prime for next event
        _hijackPrimed = true;
        _hijackPrimedDir = dir;
    }
}

document.addEventListener('wheel', (e) => {
    const target = e.target;
    if (target.tagName === 'TEXTAREA') return;
    if (target.closest('textarea')) return;
    if (target.closest('.faq-overlay.open, .levels-overlay.open')) return;

    const activeSection = document.getElementById('section-' + currentSection);
    if (!activeSection) return;
    const scrollEl = activeSection.querySelector('.section-with-profile') || activeSection;
    const atBottom = scrollEl.scrollHeight - scrollEl.scrollTop - scrollEl.clientHeight <= 5;
    const atTop    = scrollEl.scrollTop <= 0;

    if (e.deltaY > 0 && atBottom)       tryHijack(1);
    else if (e.deltaY < 0 && atTop)     tryHijack(-1);
    else { _hijackPrimed = false; _hijackPrimedDir = 0; } // U-02: cancel prime if not at boundary
}, { passive: true });

let touchStartY = 0;

document.addEventListener('touchstart', (e) => {
    touchStartY = e.touches[0].clientY;
}, { passive: true });

document.addEventListener('touchend', (e) => {
    if (hijackCooldown) return;
    const deltaY = touchStartY - e.changedTouches[0].clientY;
    if (Math.abs(deltaY) < 30) return;

    const activeSection = document.getElementById('section-' + currentSection);
    if (!activeSection) return;

    const scrollEl = activeSection.querySelector('.section-with-profile') || activeSection;
    const atBottom = scrollEl.scrollHeight - scrollEl.scrollTop - scrollEl.clientHeight <= 5;
    const atTop    = scrollEl.scrollTop <= 0;

    if (deltaY > 0 && atBottom)  tryHijack(1);
    else if (deltaY < 0 && atTop) tryHijack(-1);
}, { passive: true });

// ── RENDER TIMELINE ───────────────────────────────────────────

function renderTimeline() {
    const root = document.getElementById('timelineRoot');
    if (!root) return;
    root.innerHTML = '';

    const allEntries = [];

    // 1. Direct timeline entries from timestamp.json
    FETCHED_TIMELINE.forEach(entry => {
        const raw     = entry.date || null;
        const year    = raw
            ? parseInt(raw.split('-')[0])
            : (entry.year || new Date().getFullYear());
        const month   = raw && raw.includes('-') ? (parseInt(raw.split('-')[1]) || 0) : 0;
        const d       = raw && raw.includes('-') ? new Date(raw + (raw.split('-').length === 2 ? '-01' : '')) : null;
        const dateStr = d
            ? d.toLocaleDateString('en-US', { year: 'numeric', month: 'short' })
            : String(year);

        allEntries.push({
            year,
            month,
            title: entry.title,
            date:  dateStr,
            desc:  entry.desc || '',
            type:  entry.type || 'manual',
            id:    entry.id   || null,
        });
    });

    // 2. Project entries auto-generated from FETCHED_PROJECTS
    FETCHED_PROJECTS.forEach(info => {
        const raw     = info.date || null;
        const year    = raw
            ? parseInt(raw.split('-')[0])
            : (info.year || new Date().getFullYear());
        const month   = raw ? (parseInt(raw.split('-')[1]) || 0) : 0;
        const d       = raw ? new Date(raw + '-01') : null;
        const dateStr = d
            ? d.toLocaleDateString('en-US', { year: 'numeric', month: 'short' })
            : String(year);

        allEntries.push({
            year,
            month,
            title: info.name,
            date:  dateStr,
            desc:  info.description || '',
            type:  'project',
            id:    info.id || null,
        });
    });

    // 3. Cert entries auto-generated from FETCHED_CERTS
    FETCHED_CERTS.forEach(cert => {
        let year = new Date().getFullYear(), month = 0, d = null;
        if (cert.date) {
            const parts = cert.date.split('-');
            if (parts.length === 3 && parts[2].length === 4) {
                month = parseInt(parts[0]) || 0;
                year  = parseInt(parts[2]);
                d     = new Date(year, month - 1, 1);
            } else if (parts.length === 2) {
                year  = parseInt(parts[0]);
                month = parseInt(parts[1]) || 0;
                d     = new Date(cert.date + '-01');
            }
        }
        const dateStr = d
            ? d.toLocaleDateString('en-US', { year: 'numeric', month: 'short' })
            : String(year);

        allEntries.push({
            year,
            month,
            title: cert.title,
            date:  dateStr,
            desc:  cert.company ? `Issued by ${cert.company}` : (cert.details || ''),
            type:  'cert',
            id:    cert.id || null,
        });
    });

    // 4. Milestone entries — type:'milestone' entries from portfolio/timestamp
    FETCHED_MILESTONES.forEach(m => {
        const raw = m.date || null;
        let year    = new Date().getFullYear();
        let month   = 0;
        let dateStr = '';
        if (raw) {
            const parts = raw.split('-');
            if (parts.length === 3) {
                year        = parseInt(parts[2]);
                month       = parseInt(parts[0]) || 0;
                const d     = new Date(year, month - 1, 1);
                dateStr     = d.toLocaleDateString('en-US', { year: 'numeric', month: 'long' });
            }
        }
        allEntries.push({
            year,
            month,
            title: m.title,
            date:  dateStr,
            desc:  m.desc || '',
            type:  'milestone',
            id:    m.id   || null,
        });
    });

    // Group by year, sort descending
    const byYear = {};
    allEntries.forEach(e => {
        if (!byYear[e.year]) byYear[e.year] = [];
        byYear[e.year].push(e);
    });

    const sortedYears = Object.keys(byYear).map(Number).sort((a, b) => b - a);

    sortedYears.forEach(y => {
        byYear[y].sort((a, b) => (b.month || 0) - (a.month || 0));
    });

    if (sortedYears.length === 0) {
        root.innerHTML = `
            <div style="text-align:center;padding:40px 0;color:rgba(255,255,255,0.2);">
                <i class="fa-regular fa-clock" style="font-size:32px;margin-bottom:10px;display:block;"></i>
                No activity to timestamp.
            </div>
        `;
        return;
    }

    sortedYears.forEach((year, i) => {
        const entries = byYear[year];
        const block   = document.createElement('div');
        block.className = 'timeline-year-block';
        const isLast = i === sortedYears.length - 1;

        block.innerHTML = `
            <div class="timeline-year-row">
                <span class="timeline-year-label">${year}</span>
                <div class="timeline-line-col">
                    <div class="timeline-dot"></div>
                    ${!isLast || entries.length > 0 ? '<div class="timeline-vline"></div>' : ''}
                </div>
                <div class="timeline-entries" id="entries-${year}"></div>
            </div>
        `;

        root.appendChild(block);

        const entriesEl = document.getElementById('entries-' + year);

        entries.forEach(entry => {
            const el = document.createElement('div');
            el.className = 'timeline-entry';
            if (entry.type === 'milestone') el.classList.add('milestone');

            const learnMoreHTML = (entry.type === 'project' || entry.type === 'cert' || entry.type === 'education')
                ? `<button class="timeline-learn-more">Learn More <i class="fa-solid fa-arrow-right"></i></button>`
                : '';

            const milestoneDeleteHTML = entry.type === 'milestone'
                ? `<button class="milestone-delete" title="Delete milestone" aria-label="Delete milestone"><i class="fa-solid fa-xmark"></i></button>`
                : '';

            el.innerHTML = `
                ${milestoneDeleteHTML}
                <div class="timeline-entry-body">
                    <span class="timeline-entry-title">${sanitize(entry.title)}</span>
                    ${entry.desc ? `<span class="timeline-entry-desc">${sanitize(entry.desc)}</span>` : ''}
                </div>
                <div class="timeline-entry-reveal">
                    <div class="timeline-entry-reveal-inner">
                        <span class="timeline-entry-date">${entry.date}</span>
                        ${learnMoreHTML}
                    </div>
                </div>
            `;

            el.addEventListener('click', (e) => {
                if (e.target.closest('.timeline-learn-more')) return;
                if (e.target.closest('.milestone-delete')) return;
                const isExpanded = el.classList.contains('expanded');
                document.querySelectorAll('.timeline-entry.expanded').forEach(c => c.classList.remove('expanded'));
                if (!isExpanded) el.classList.add('expanded');
            });

            const learnMoreBtn = el.querySelector('.timeline-learn-more');
            if (learnMoreBtn) {
                learnMoreBtn.addEventListener('click', (e) => {
                    e.stopPropagation();

                    if (entry.type === 'project') {
                        switchSection('projects');
                        setTimeout(() => {
                            document.querySelectorAll('.project-card').forEach(card => {
                                const matchById   = entry.id && card.dataset.projectId === entry.id;
                                const matchByName = !entry.id && card.querySelector('.project-name')?.textContent.trim() === entry.title;
                                if (matchById || matchByName) {
                                    card.classList.add('highlight');
                                    card.scrollIntoView({ behavior: 'smooth', block: 'center' });
                                    setTimeout(() => card.classList.remove('highlight'), 1500);
                                }
                            });
                        }, 350);
                    } else if (entry.type === 'cert') {
                        switchSection('certificates');
                        setTimeout(() => {
                            document.querySelectorAll('.cert-card').forEach(card => {
                                const matchById   = entry.id && card.dataset.certId === entry.id;
                                const matchByName = !entry.id && card.querySelector('.cert-card-title')?.textContent.trim() === entry.title;
                                if (matchById || matchByName) {
                                    card.classList.add('highlight');
                                    card.scrollIntoView({ behavior: 'smooth', block: 'center' });
                                    setTimeout(() => card.classList.remove('highlight'), 1500);
                                }
                            });
                        }, 350);
                    } else if (entry.type === 'education') {
                        switchSection('about');
                        setTimeout(() => {
                            document.querySelectorAll('.about-edu-card').forEach(card => {
                                const matchByDegree = card.querySelector('.about-edu-degree')?.textContent.trim() === entry.title;
                                if (matchByDegree) {
                                    card.classList.add('highlight');
                                    card.scrollIntoView({ behavior: 'smooth', block: 'center' });
                                    setTimeout(() => card.classList.remove('highlight'), 1500);
                                }
                            });
                        }, 350);
                    }
                });
            }

            const milestoneDeleteBtn = el.querySelector('.milestone-delete');
            if (milestoneDeleteBtn) {
                milestoneDeleteBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    openMilestoneDeleteModal(entry);
                });
            }

            entriesEl.appendChild(el);
        });
    });
}

// ── RENDER PROJECTS ───────────────────────────────────────────

function renderProjects() {
    const root = document.getElementById('projectsRoot');
    if (!root) return;
    root.innerHTML = '';

    if (FETCHED_PROJECTS.length === 0) {
        root.innerHTML = `
            <div style="text-align:center;padding:40px 0;color:rgba(255,255,255,0.2);">
                <i class="fa-solid fa-code" style="font-size:32px;margin-bottom:10px;display:block;"></i>
                No projects yet.
            </div>
        `;
        return;
    }

    const byYear = {};
    FETCHED_PROJECTS.forEach(info => {
        const y = info.date ? parseInt(info.date.split('-')[0]) : new Date().getFullYear();
        if (!byYear[y]) byYear[y] = [];
        byYear[y].push(info);
    });

    Object.keys(byYear).sort((a, b) => b - a).forEach(year => {
        const group = document.createElement('div');
        group.className = 'projects-year-group';
        group.innerHTML = `<div class="projects-year-label">${year}</div>`;

        const grid = document.createElement('div');
        grid.className = 'projects-grid';

        byYear[year].forEach(info => {
            const card = document.createElement('div');
            card.className = 'project-card';

            if (info.id)    card.dataset.projectId   = info.id;
            if (info._repo) card.dataset.projectRepo = info._repo;

            const tagsHTML = (info.stack || []).map(t => `<span class="project-tag">${sanitize(t)}</span>`).join('');

            // S-04: info.live and info.source validated to https:// before use as href,
            // then passed through sanitize(). A javascript: or data: value is silently
            // treated as absent and falls back to the "NO LIVE" / empty state.
            const liveBtnHTML = info.live && isSafeUrl(info.live)
                ? `<a href="${sanitize(info.live)}" target="_blank" rel="noopener noreferrer" class="doc-card-btn view"><i class="fa-solid fa-arrow-up-right-from-square"></i> LIVE</a>`
                : `<span class="doc-card-btn view" style="opacity:0.3;cursor:not-allowed;pointer-events:none;"><i class="fa-solid fa-ban"></i> NO LIVE</span>`;

            const sourceBtnHTML = info.source && isSafeUrl(info.source)
                ? `<a href="${sanitize(info.source)}" target="_blank" rel="noopener noreferrer" class="doc-card-btn download"><i class="fa-brands fa-github"></i> SOURCE</a>`
                : '';

            // S-04: info.banner passed through sanitize(); alt also sanitized.
            const previewHTML = info.banner
                ? `<img src="${sanitize(info.banner)}" alt="${sanitize(info.name || '')}" class="project-card-banner">`
                : `<i class="fa-solid fa-code project-card-placeholder-icon"></i>`;

            const contribHTML = info.contributions
                ? `<div class="project-card-contribution">${sanitize(info.contributions)}</div>`
                : '';

            card.innerHTML = `
                <button class="project-card-delete" title="Delete project" aria-label="Delete project">
                    <i class="fa-solid fa-xmark"></i>
                </button>
                <div class="project-card-preview">${previewHTML}</div>
                <div class="project-card-body">
                    <div class="project-card-type">PROJECT</div>
                    <div class="project-name">${sanitize(info.name)}</div>
                    <div class="project-desc">${sanitize(info.description || '')}</div>
                    <div class="project-tags">${tagsHTML}</div>
                </div>
                <div class="project-card-expand">
                    <div class="project-card-expand-inner">
                        ${contribHTML}
                        <div class="project-card-actions">
                            ${liveBtnHTML}${sourceBtnHTML}
                        </div>
                    </div>
                </div>
            `;

            const img = card.querySelector('.project-card-banner');
            if (img) {
                img.addEventListener('error', () => {
                    img.replaceWith(Object.assign(
                        document.createElement('i'),
                        { className: 'fa-solid fa-code project-card-placeholder-icon' }
                    ));
                });
            }

            const deleteBtn = card.querySelector('.project-card-delete');
            if (deleteBtn) {
                deleteBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    openProjectDeleteModal({ repo: info._repo, name: info.name });
                });
            }

            card.addEventListener('click', (e) => {
                if (e.target.closest('.project-card-actions')) return;
                if (e.target.closest('.project-card-delete')) return;
                const isExpanded = card.classList.contains('expanded');
                document.querySelectorAll('.project-card.expanded').forEach(c => c.classList.remove('expanded'));
                if (!isExpanded) card.classList.add('expanded');
            });

            grid.appendChild(card);
        });

        group.appendChild(grid);
        root.appendChild(group);
    });
}

// ── RENDER DOC CARD ───────────────────────────────────────────

function renderDocCard(data) {
    const card = document.createElement('div');
    card.className = 'doc-card';

    // Store identifiers for delete
    if (data.id)   card.dataset.docId   = data.id;
    if (data.file) card.dataset.docFile = data.file;
    if (data.type) card.dataset.docType = data.type;

    const dateStr = data.uploaded
        ? new Date(data.uploaded).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })
        : 'Date unknown';

    const encodedPath = data.file
        ? data.file.split('/').map(encodeURIComponent).join('/')
        : null;

    const rawUrl    = encodedPath
        ? `https://raw.githubusercontent.com/devssst/my-portfolio/main/${encodedPath}`
        : null;
    const viewerUrl = encodedPath
        ? `https://github.com/devssst/my-portfolio/blob/main/${encodedPath}`
        : null;

    card.innerHTML = `
        <button class="doc-card-delete" title="Delete document" aria-label="Delete document">
            <i class="fa-solid fa-xmark"></i>
        </button>
        <div class="doc-card-preview">
            <i class="fa-regular fa-file-pdf doc-card-placeholder-icon"></i>
        </div>
        <div class="doc-card-body">
            <div class="doc-card-type">${sanitize((data.type || 'DOCUMENT')).toUpperCase()}</div>
            <div class="doc-card-title">${sanitize(data.title)}</div>
            <div class="doc-card-date">${dateStr}</div>
        </div>
        <div class="doc-card-expand">
            <div class="doc-card-actions">
                <a href="${viewerUrl || '#'}" target="_blank" class="doc-card-btn view">
                    <i class="fa-solid fa-eye"></i> VIEW
                </a>
                <button type="button" class="doc-card-btn download">
                    <i class="fa-solid fa-download"></i> SAVE
                </button>
            </div>
        </div>
    `;

    // SAVE 
    const saveBtn = card.querySelector('.doc-card-btn.download');
    if (saveBtn && rawUrl) {
        saveBtn.addEventListener('click', async (e) => {
            e.stopPropagation();
            try {
                const res     = await fetch(rawUrl);
                const blob    = await res.blob();
                const blobUrl = URL.createObjectURL(blob);
                const a       = document.createElement('a');
                a.href        = blobUrl;
                a.download    = (data.title || 'document') + '.pdf';
                a.click();
                setTimeout(() => URL.revokeObjectURL(blobUrl), 10000);
            } catch {}
        });
    }

    if (rawUrl && window.pdfjsLib) {
        const previewEl   = card.querySelector('.doc-card-preview');
        const placeholder = previewEl.querySelector('.doc-card-placeholder-icon');

        pdfjsLib.getDocument(rawUrl).promise
            .then(pdf => pdf.getPage(1))
            .then(page => {
                const viewport = page.getViewport({ scale: 1 });
                const scale    = 220 / viewport.width;
                const scaled   = page.getViewport({ scale });

                const canvas     = document.createElement('canvas');
                canvas.className = 'doc-card-canvas';
                canvas.width     = scaled.width;
                canvas.height    = scaled.height;

                return page.render({
                    canvasContext: canvas.getContext('2d'),
                    viewport: scaled
                }).promise.then(() => {
                    placeholder.remove();
                    previewEl.appendChild(canvas);
                });
            })
            .catch(() => {});
    }

    // Delete button 
    const deleteBtn = card.querySelector('.doc-card-delete');
    if (deleteBtn) {
        deleteBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            openDocDeleteModal(data);
        });
    }

    card.addEventListener('click', (e) => {
        if (e.target.closest('.doc-card-actions')) return;
        if (e.target.closest('.doc-card-delete')) return;
        const isExpanded = card.classList.contains('expanded');
        document.querySelectorAll('.doc-card.expanded').forEach(c => c.classList.remove('expanded'));
        if (!isExpanded) card.classList.add('expanded');
    });

    return card;
}

// ── RENDER DOCS ───────────────────────────────────────────────

async function renderDocs() {
    const grid = document.getElementById('homeDocsGrid');
    if (!grid) return;

    let docData = null;

    try {
        const snap = await getDoc(doc(_dDb, "portfolio", "docs"));
        if (snap.exists()) {
            const json = snap.data().data || {};
            docData = {
                cv:     json.cv     || [],
                resume: json.resume || []
            };
        }
    } catch {}

    if (!docData) docData = { cv: [], resume: [] };

    grid.innerHTML = '';

    const allDocs = [
        ...docData.cv.map(d => ({ ...d, type: 'CV' })),
        ...docData.resume.map(d => ({ ...d, type: 'Resume' }))
    ];

    if (allDocs.length === 0) {
        grid.innerHTML = `
            <div data-empty-state style="text-align:center;padding:40px 0;color:rgba(255,255,255,0.2);width:100%;">
                <i class="fa-regular fa-folder-open" style="font-size:32px;margin-bottom:10px;display:block;"></i>
                No documents yet.
            </div>
        `;
    } else {
        allDocs.forEach(d => grid.appendChild(renderDocCard(d)));
    }
    if (isEditMode) injectDocUploadBtn();
}

// ── EDIT MODE ─────────────────────────────────────────────────

function setEditMode(active) {
    isEditMode = active;

    const grid         = document.getElementById('homeDocsGrid');
    const timelineRoot = document.getElementById('timelineRoot');
    const projectsRoot = document.getElementById('projectsRoot');
    const certsRoot    = document.getElementById('certsRoot');

    if (active) {
        if (grid)         grid.classList.add('edit-active');
        if (timelineRoot) timelineRoot.classList.add('edit-active');
        if (projectsRoot) projectsRoot.classList.add('edit-active');
        if (certsRoot)    certsRoot.classList.add('edit-active');
        injectDocUploadBtn();
        injectMilestoneAddBtn();
        injectProjectAddBtn();
        injectCertAddBtn();
    } else {
        if (grid)         grid.classList.remove('edit-active');
        if (timelineRoot) timelineRoot.classList.remove('edit-active');
        if (projectsRoot) projectsRoot.classList.remove('edit-active');
        if (certsRoot)    certsRoot.classList.remove('edit-active');
        const btn = document.getElementById('docUploadBtn');
        if (btn) {
            btn.remove();
            if (grid && grid.children.length === 0) {
                grid.innerHTML = `
                    <div data-empty-state style="text-align:center;padding:40px 0;color:rgba(255,255,255,0.2);width:100%;">
                        <i class="fa-regular fa-folder-open" style="font-size:32px;margin-bottom:10px;display:block;"></i>
                        No documents yet.
                    </div>
                `;
            }
        }
        const mBtn = document.getElementById('milestoneAddBtn');
        if (mBtn) mBtn.remove();
        const pBtn = document.getElementById('projectAddBtn');
        if (pBtn) pBtn.remove();
        const cBtn = document.getElementById('certAddBtn');
        if (cBtn) cBtn.remove();
    }

    _injectEduDeleteBtns();
    updateAboutEditBtnVisibility();
}

function _injectEduDeleteBtns() {
    const eduList = document.getElementById('aboutEduList');
    if (!eduList) return;

    eduList.querySelectorAll('.edu-card-delete').forEach(b => b.remove());

    if (!isEditMode) return;

    eduList.querySelectorAll('.about-edu-card').forEach(card => {
        const idx = parseInt(card.dataset.eduIdx, 10);
        const btn = document.createElement('button');
        btn.className   = 'edu-card-delete';
        btn.title       = 'Remove education';
        btn.ariaLabel   = 'Remove education';
        btn.innerHTML   = '<i class="fa-solid fa-xmark"></i>';
        btn.addEventListener('click', () => {
            eduDeleteTargetIdx = idx;
            openEduDeleteModal();
        });
        card.classList.add('edit-active');
        card.insertBefore(btn, card.firstChild);
    });
}

function injectDocUploadBtn() {
    if (document.getElementById('docUploadBtn')) return; // already present

    const grid = document.getElementById('homeDocsGrid');
    if (!grid) return;

    const emptyState = grid.querySelector('[data-empty-state]');
    if (emptyState) emptyState.remove();

    const btn = document.createElement('button');
    btn.id        = 'docUploadBtn';
    btn.className = 'doc-upload-btn';
    btn.type      = 'button';
    btn.innerHTML = `
        <i class="fa-solid fa-file-arrow-up doc-upload-icon"></i>
        <span class="doc-upload-label">New Document</span>
    `;
    btn.addEventListener('click', openDocUploadModal);
    grid.appendChild(btn);
}

function injectMilestoneAddBtn() {
    if (document.getElementById('milestoneAddBtn')) return; // guard: already present
    const heading = document.querySelector('#timelineContent .section-heading');
    if (!heading) return;
    const btn = document.createElement('button');
    btn.id        = 'milestoneAddBtn';
    btn.className = 'milestone-add-btn';
    btn.type      = 'button';
    btn.innerHTML = '<i class="fa-solid fa-plus"></i> Add Milestone';
    btn.addEventListener('click', openMilestoneAddModal);
    heading.appendChild(btn);
}

function injectProjectAddBtn() {
    if (document.getElementById('projectAddBtn')) return;
    const heading = document.querySelector('#projectsContent .section-heading');
    if (!heading) return;
    const btn = document.createElement('button');
    btn.id        = 'projectAddBtn';
    btn.className = 'project-add-btn';
    btn.type      = 'button';
    btn.innerHTML = '<i class="fa-solid fa-plus"></i> New Project';
    btn.addEventListener('click', openProjectAddModal);
    heading.appendChild(btn);
}

function injectCertAddBtn() {
    if (document.getElementById('certAddBtn')) return;
    const heading = document.querySelector('#certificatesContent .section-heading');
    if (!heading) return;
    const btn = document.createElement('button');
    btn.id        = 'certAddBtn';
    btn.className = 'cert-add-btn';
    btn.type      = 'button';
    btn.innerHTML = '<i class="fa-solid fa-plus"></i> Add Certificate';
    btn.addEventListener('click', openCertUploadModal);
    heading.appendChild(btn);
}

// ── PROJECT ADD MODAL ─────────────────────────────────────────

const projectAddOverlay  = document.getElementById('projectAddOverlay');
const projectAddClose    = document.getElementById('projectAddClose');
const projectRepoInput   = document.getElementById('projectRepoInput');
const projectDateInput   = document.getElementById('projectDateInput');
const projectAddSubmit   = document.getElementById('projectAddSubmit');
const projectAddStatus   = document.getElementById('projectAddStatus');

function openProjectAddModal() {
    if (projectRepoInput) projectRepoInput.value = '';
    if (projectDateInput) projectDateInput.value = '';
    if (projectAddStatus) { projectAddStatus.textContent = ''; projectAddStatus.className = 'doc-upload-status'; }
    if (projectAddSubmit) { projectAddSubmit.disabled = false; projectAddSubmit.innerHTML = '<i class="fa-brands fa-github"></i> Add Project'; }
    if (projectAddOverlay) projectAddOverlay.classList.add('open');
}

function closeProjectAddModal() {
    if (projectAddOverlay) projectAddOverlay.classList.remove('open');
}

function setProjectAddStatus(msg, type) {
    if (!projectAddStatus) return;
    projectAddStatus.textContent = msg;
    projectAddStatus.className   = 'doc-upload-status' + (type ? ` ${type}` : '');
}

if (projectAddClose) projectAddClose.addEventListener('click', closeProjectAddModal);
if (projectAddOverlay) {
    projectAddOverlay.addEventListener('click', (e) => {
        if (e.target === projectAddOverlay) closeProjectAddModal();
    });
}
if (projectAddSubmit) projectAddSubmit.addEventListener('click', handleProjectAdd);

async function handleProjectAdd() {
    const raw  = (projectRepoInput?.value || '').trim();
    const repo = raw.replace(/^https?:\/\/github\.com\//, '').replace(/\/$/, '');
    const date = (projectDateInput?.value || '').trim(); // YYYY-MM from type="month"

    if (!repo || !repo.includes('/')) {
        setProjectAddStatus('Enter a valid repo slug e.g. nickname/project-repo', 'error');
        if (projectRepoInput) projectRepoInput.focus();
        return;
    }

    if (!date) {
        setProjectAddStatus('Please select a month and year.', 'error');
        if (projectDateInput) projectDateInput.focus();
        return;
    }

    projectAddSubmit.disabled = true;
    projectAddSubmit.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Verifying...';
    setProjectAddStatus('', '');

    try {
        // Verify INFO.json exists and is valid
        const res = await fetch(`https://raw.githubusercontent.com/${repo}/main/INFO.json?t=${Date.now()}`);
        if (!res.ok) {
            setProjectAddStatus(`Could not fetch INFO.json from ${repo} — is the repo public and does INFO.json exist?`, 'error');
            projectAddSubmit.disabled = false;
            projectAddSubmit.innerHTML = '<i class="fa-brands fa-github"></i> Add Project';
            return;
        }
        const infoData = await res.json();

        projectAddSubmit.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Saving...';

        // Read current timestamp doc
        const snap   = await getDoc(doc(_dDb, "portfolio", "timestamp"));
        let tsData   = snap.exists() ? (snap.data().data || []) : [];

        // Guard against duplicate
        if (tsData.some(e => e.repo === repo)) {
            setProjectAddStatus('This repo is already in the list.', 'error');
            projectAddSubmit.disabled = false;
            projectAddSubmit.innerHTML = '<i class="fa-brands fa-github"></i> Add Project';
            return;
        }

        // B-06: arrayUnion atomically appends — concurrent adds from other tabs are preserved
        const newEntry = { repo, date };
        await updateDoc(doc(_dDb, "portfolio", "timestamp"), { data: arrayUnion(newEntry) });

        // Update local cache
        FETCHED_PROJECTS.push({ ...infoData, _repo: repo, date });

        renderProjects();
        renderTimeline();
        populateStats();
        if (isEditMode) injectProjectAddBtn();

        setProjectAddStatus(`"${infoData.name || repo}" added!`, 'success');
        setTimeout(() => closeProjectAddModal(), 1200);

    } catch (err) {
        console.error('Project add error:', err);
        setProjectAddStatus(`Failed: ${err.message || 'Unknown error'}`, 'error');
        projectAddSubmit.disabled = false;
        projectAddSubmit.innerHTML = '<i class="fa-brands fa-github"></i> Add Project';
    }
}

// ── PROJECT DELETE MODAL ──────────────────────────────────────

let pendingDeleteProject = null;

const projectDeleteOverlay = document.getElementById('projectDeleteOverlay');
const projectDeleteClose   = document.getElementById('projectDeleteClose');
const projectDeleteCancel  = document.getElementById('projectDeleteCancel');
const projectDeleteConfirm = document.getElementById('projectDeleteConfirm');
const projectDeleteTitle   = document.getElementById('projectDeleteTitle');

function openProjectDeleteModal(data) {
    pendingDeleteProject = data;
    if (projectDeleteTitle) projectDeleteTitle.textContent = data.name || data.repo || 'this project';
    if (projectDeleteConfirm) {
        projectDeleteConfirm.disabled = false;
        projectDeleteConfirm.innerHTML = '<i class="fa-solid fa-trash"></i> YES, DELETE';
    }
    if (projectDeleteOverlay) projectDeleteOverlay.classList.add('open');
}

function closeProjectDeleteModal() {
    if (projectDeleteOverlay) projectDeleteOverlay.classList.remove('open');
    pendingDeleteProject = null;
}

if (projectDeleteClose)  projectDeleteClose.addEventListener('click',  closeProjectDeleteModal);
if (projectDeleteCancel) projectDeleteCancel.addEventListener('click', closeProjectDeleteModal);
if (projectDeleteOverlay) {
    projectDeleteOverlay.addEventListener('click', (e) => {
        if (e.target === projectDeleteOverlay) closeProjectDeleteModal();
    });
}
if (projectDeleteConfirm) projectDeleteConfirm.addEventListener('click', handleProjectDelete);

async function handleProjectDelete() {
    if (!pendingDeleteProject) return;
    const { repo } = pendingDeleteProject;

    projectDeleteConfirm.disabled = true;
    projectDeleteConfirm.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Deleting...';

    try {
        const snap  = await getDoc(doc(_dDb, "portfolio", "timestamp"));
        const tsData = snap.exists() ? (snap.data().data || []) : [];
        // B-06: arrayRemove only removes this entry — other tabs' concurrent adds survive
        const entryToRemove = tsData.find(e => e.repo === repo);
        if (entryToRemove) {
            await updateDoc(doc(_dDb, "portfolio", "timestamp"), { data: arrayRemove(entryToRemove) });
        }

        // Update local cache — no longer reading tsData post-write
        FETCHED_PROJECTS = FETCHED_PROJECTS.filter(p => p._repo !== repo);

        closeProjectDeleteModal();
        renderProjects();
        renderTimeline();
        populateStats();

    } catch (err) {
        console.error('Project delete error:', err);
        projectDeleteConfirm.disabled = false;
        projectDeleteConfirm.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> FAILED';
        setTimeout(() => { projectDeleteConfirm.innerHTML = '<i class="fa-solid fa-trash"></i> YES, DELETE'; }, 2000);
    }
}

const milestoneAddOverlay  = document.getElementById('milestoneAddOverlay');
const milestoneAddClose    = document.getElementById('milestoneAddClose');
const milestoneTitleInput  = document.getElementById('milestoneTitle');
const milestoneDescInput   = document.getElementById('milestoneDesc');
const milestoneDateInput   = document.getElementById('milestoneDate');
const milestoneAddSubmit   = document.getElementById('milestoneAddSubmit');
const milestoneAddStatus   = document.getElementById('milestoneAddStatus');

function openMilestoneAddModal() {
    resetMilestoneAddModal();
    if (milestoneAddOverlay) milestoneAddOverlay.classList.add('open');
}

function closeMilestoneAddModal() {
    if (milestoneAddOverlay) milestoneAddOverlay.classList.remove('open');
}

function resetMilestoneAddModal() {
    if (milestoneTitleInput) milestoneTitleInput.value = '';
    if (milestoneDescInput)  milestoneDescInput.value  = '';
    if (milestoneDateInput)  milestoneDateInput.value  = '';
    if (milestoneAddStatus) {
        milestoneAddStatus.textContent = '';
        milestoneAddStatus.className   = 'doc-upload-status';
    }
    if (milestoneAddSubmit) {
        milestoneAddSubmit.disabled = false;
        milestoneAddSubmit.innerHTML = '<i class="fa-solid fa-flag-checkered"></i> Save Milestone';
    }
}

function setMilestoneStatus(msg, type) {
    if (!milestoneAddStatus) return;
    milestoneAddStatus.textContent = msg;
    milestoneAddStatus.className   = 'doc-upload-status' + (type ? ` ${type}` : '');
}

if (milestoneAddClose) {
    milestoneAddClose.addEventListener('click', closeMilestoneAddModal);
}

if (milestoneAddOverlay) {
    milestoneAddOverlay.addEventListener('click', (e) => {
        if (e.target === milestoneAddOverlay) closeMilestoneAddModal();
    });
}

if (milestoneAddSubmit) {
    milestoneAddSubmit.addEventListener('click', handleMilestoneAdd);
}

async function handleMilestoneAdd() {
    const title   = milestoneTitleInput?.value.trim() || '';
    const desc    = milestoneDescInput?.value.trim()  || '';
    const dateVal = milestoneDateInput?.value          || ''; // YYYY-MM-DD from native date input

    if (!title) {
        setMilestoneStatus('Please enter a title.', 'error');
        if (milestoneTitleInput) milestoneTitleInput.focus();
        return;
    }
    if (!dateVal) {
        setMilestoneStatus('Please select a date.', 'error');
        if (milestoneDateInput) milestoneDateInput.focus();
        return;
    }

    // Convert YYYY-MM-DD → MM-DD-YYYY for storage
    const parts      = dateVal.split('-');
    const dateStored = `${parts[1]}-${parts[2]}-${parts[0]}`;

    if (milestoneAddSubmit) {
        milestoneAddSubmit.disabled = true;
        milestoneAddSubmit.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Saving...';
    }
    setMilestoneStatus('', '');

    try {
        const id    = `milestone-${Date.now()}`;
        const entry = { id, type: 'milestone', title, desc, date: dateStored };

        // B-06: arrayUnion atomically appends — no full pre-read needed
        await updateDoc(doc(_dDb, "portfolio", "timestamp"), { data: arrayUnion(entry) });

        // Update local caches directly
        FETCHED_MILESTONES = [...FETCHED_MILESTONES, entry];
        renderTimeline();

        if (isEditMode) injectMilestoneAddBtn();

        setMilestoneStatus('Milestone saved!', 'success');
        setTimeout(() => closeMilestoneAddModal(), 1200);

    } catch (err) {
        console.error('Milestone save error:', err);
        setMilestoneStatus(`Failed: ${err.message || 'Unknown error'}`, 'error');
        if (milestoneAddSubmit) {
            milestoneAddSubmit.disabled = false;
            milestoneAddSubmit.innerHTML = '<i class="fa-solid fa-flag-checkered"></i> Save Milestone';
        }
    }
}

// ── MILESTONE DELETE MODAL ────────────────────────────────────

let pendingDeleteMilestone = null;

const milestoneDeleteOverlay = document.getElementById('milestoneDeleteOverlay');
const milestoneDeleteClose   = document.getElementById('milestoneDeleteClose');
const milestoneDeleteCancel  = document.getElementById('milestoneDeleteCancel');
const milestoneDeleteConfirm = document.getElementById('milestoneDeleteConfirm');
const milestoneDeleteTitle   = document.getElementById('milestoneDeleteTitle');

function openMilestoneDeleteModal(data) {
    pendingDeleteMilestone = data;
    if (milestoneDeleteTitle) milestoneDeleteTitle.textContent = data.title || 'this milestone';
    if (milestoneDeleteConfirm) {
        milestoneDeleteConfirm.disabled = false;
        milestoneDeleteConfirm.innerHTML = '<i class="fa-solid fa-trash"></i> YES, DELETE';
    }
    if (milestoneDeleteOverlay) milestoneDeleteOverlay.classList.add('open');
}

function closeMilestoneDeleteModal() {
    if (milestoneDeleteOverlay) milestoneDeleteOverlay.classList.remove('open');
    pendingDeleteMilestone = null;
}

if (milestoneDeleteClose)  milestoneDeleteClose.addEventListener('click',  closeMilestoneDeleteModal);
if (milestoneDeleteCancel) milestoneDeleteCancel.addEventListener('click', closeMilestoneDeleteModal);
if (milestoneDeleteOverlay) {
    milestoneDeleteOverlay.addEventListener('click', (e) => {
        if (e.target === milestoneDeleteOverlay) closeMilestoneDeleteModal();
    });
}

if (milestoneDeleteConfirm) {
    milestoneDeleteConfirm.addEventListener('click', handleMilestoneDelete);
}

async function handleMilestoneDelete() {
    if (!pendingDeleteMilestone) return;
    const { id } = pendingDeleteMilestone;

    milestoneDeleteConfirm.disabled = true;
    milestoneDeleteConfirm.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Deleting...';

    try {
        const snap   = await getDoc(doc(_dDb, "portfolio", "timestamp"));
        const tsData = snap.exists() ? (snap.data().data || []) : [];
        // B-06: arrayRemove only removes this entry — other tabs' concurrent adds survive
        const entryToRemove = tsData.find(e => e.id === id);
        if (entryToRemove) {
            await updateDoc(doc(_dDb, "portfolio", "timestamp"), { data: arrayRemove(entryToRemove) });
        }

        FETCHED_MILESTONES = FETCHED_MILESTONES.filter(e => e.id !== id);
        // FETCHED_TIMELINE never contains milestones — no update needed

        closeMilestoneDeleteModal();
        renderTimeline();

    } catch (err) {
        console.error('Milestone delete error:', err);
        milestoneDeleteConfirm.disabled = false;
        milestoneDeleteConfirm.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> FAILED';
        setTimeout(() => { milestoneDeleteConfirm.innerHTML = '<i class="fa-solid fa-trash"></i> YES, DELETE'; }, 2000);
    }
}

// ── DOC UPLOAD MODAL ──────────────────────────────────────────

let selectedDocFile = null;

const docUploadOverlay = document.getElementById('docUploadOverlay');
const docUploadClose   = document.getElementById('docUploadClose');
const docDropZone      = document.getElementById('docDropZone');
const docFileInput     = document.getElementById('docFileInput');
const docDropBrowse    = document.getElementById('docDropBrowse');
const docDropFileName  = document.getElementById('docDropFileName');
const docTitleInput    = document.getElementById('docTitleInput');
const docTypeSelect    = document.getElementById('docTypeSelect');
const docUploadSubmit  = document.getElementById('docUploadSubmit');
const docUploadStatus  = document.getElementById('docUploadStatus');

function openDocUploadModal() {
    resetDocUploadModal();
    if (docUploadOverlay) docUploadOverlay.classList.add('open');
}

function closeDocUploadModal() {
    if (docUploadOverlay) docUploadOverlay.classList.remove('open');
}

function resetDocUploadModal() {
    selectedDocFile = null;

    if (docDropZone)     { docDropZone.classList.remove('drag-over', 'has-file'); }
    if (docDropFileName) { docDropFileName.textContent = 'No file selected'; docDropFileName.classList.remove('has-file'); }
    if (docTitleInput)   { docTitleInput.value = ''; }
    if (docTypeSelect)   { docTypeSelect.value = 'resume'; }
    if (docFileInput)    { docFileInput.value = ''; }
    if (docUploadStatus) { docUploadStatus.textContent = ''; docUploadStatus.className = 'doc-upload-status'; }
    if (docUploadSubmit) { docUploadSubmit.disabled = false; docUploadSubmit.innerHTML = '<i class="fa-solid fa-cloud-arrow-up"></i> Upload'; }
}

function handleFileSelected(file) {
    if (!file) return;
    if (file.type !== 'application/pdf') {
        setUploadStatus('Only PDF files are accepted.', 'error');
        return;
    }

    selectedDocFile = file;

    // Update drop zone
    if (docDropZone)     docDropZone.classList.add('has-file');
    if (docDropFileName) { docDropFileName.textContent = file.name; docDropFileName.classList.add('has-file'); }

    // Auto-fill title from filename (strip extension)
    if (docTitleInput && !docTitleInput.value) {
        docTitleInput.value = file.name.replace(/\.[^/.]+$/, '');
    }

    setUploadStatus('', '');
}

function setUploadStatus(msg, type) {
    if (!docUploadStatus) return;
    docUploadStatus.textContent = msg;
    docUploadStatus.className   = 'doc-upload-status' + (type ? ` ${type}` : '');
}

// Close on overlay backdrop click
if (docUploadOverlay) {
    docUploadOverlay.addEventListener('click', (e) => {
        if (e.target === docUploadOverlay) closeDocUploadModal();
    });
}

if (docUploadClose) {
    docUploadClose.addEventListener('click', closeDocUploadModal);
}

// Browse button triggers hidden file input
if (docDropBrowse) {
    docDropBrowse.addEventListener('click', (e) => {
        e.stopPropagation();
        if (docFileInput) docFileInput.click();
    });
}

// Clicking anywhere in zone also opens file picker (except browse button)
if (docDropZone) {
    docDropZone.addEventListener('click', (e) => {
        if (e.target === docDropBrowse || e.target.closest('.doc-drop-browse')) return;
        if (docFileInput) docFileInput.click();
    });
}

// File input change
if (docFileInput) {
    docFileInput.addEventListener('change', () => {
        if (docFileInput.files && docFileInput.files[0]) {
            handleFileSelected(docFileInput.files[0]);
        }
    });
}

// Drag & drop events
if (docDropZone) {
    docDropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        docDropZone.classList.add('drag-over');
    });

    docDropZone.addEventListener('dragleave', (e) => {
        if (!docDropZone.contains(e.relatedTarget)) {
            docDropZone.classList.remove('drag-over');
        }
    });

    docDropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        docDropZone.classList.remove('drag-over');
        const file = e.dataTransfer?.files?.[0] || null;
        if (file) handleFileSelected(file);
    });
}

// Upload handler
if (docUploadSubmit) {
    docUploadSubmit.addEventListener('click', handleDocUpload);
}

async function handleDocUpload() {
    if (!selectedDocFile) {
        setUploadStatus('Please select a PDF file first.', 'error');
        return;
    }

    const title = docTitleInput?.value.trim() || '';
    if (!title) {
        setUploadStatus('Please enter a document title.', 'error');
        if (docTitleInput) docTitleInput.focus();
        return;
    }

    if (!GH_TOKEN || !GH_OWNER || !GH_REPO) {
        setUploadStatus('GitHub credentials not loaded. Try again.', 'error');
        return;
    }

    // Disable button and show loading
    if (docUploadSubmit) {
        docUploadSubmit.disabled = true;
        docUploadSubmit.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Uploading...';
    }
    setUploadStatus('', '');

    try {
        // Auto-generate fields
        const id           = `doc-${Date.now()}`;
        const rawFileName  = selectedDocFile.name;
        // FIX: sanitize filename — replace spaces and unsafe chars before building path
        const fileName     = rawFileName.replace(/\s+/g, '-').replace(/[^a-zA-Z0-9._-]/g, '');
        const filePath     = `data/files/${fileName}`;
        const uploaded = new Date().toISOString().split('T')[0];
        const typeKey  = docTypeSelect?.value || 'resume'; // 'resume' | 'cv'
        const typeLabel = typeKey === 'cv' ? 'CV' : 'Resume';

        // Base64 encode
        const base64 = await new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload  = () => resolve(reader.result.split(',')[1]);
            reader.onerror = reject;
            reader.readAsDataURL(selectedDocFile);
        });

        setUploadStatus('Pushing to GitHub...', '');

        // FIX: fetch existing SHA so re-uploading same filename works
        const existingSha = await ghGetSHA(filePath);
        await ghPushFile(filePath, base64, `Add document: ${fileName}`, existingSha);

        setUploadStatus('Saving to Firestore...', '');

        // B-07: Pre-read to detect an existing entry for the same filePath.
        // ghGetSHA already replaced the file on GitHub — without this check a second
        // Firestore entry would be created pointing to the same path, orphaning one
        // card after the first deletion.
        const docsSnap    = await getDoc(doc(_dDb, "portfolio", "docs"));
        const docsData    = docsSnap.exists() ? (docsSnap.data().data || {}) : {};
        const currentArr  = docsData[typeKey] || [];
        const existingIdx = currentArr.findIndex(e => e.file === filePath);

        if (existingIdx >= 0) {
            // Same filename already has a metadata entry — update it in place,
            // preserving its original id so no existing references break.
            const updated = [...currentArr];
            updated[existingIdx] = { ...currentArr[existingIdx], title, type: typeLabel, uploaded };
            await updateDoc(doc(_dDb, "portfolio", "docs"), { [`data.${typeKey}`]: updated });
            setUploadStatus('File replaced — existing entry updated.', 'success');
        } else {
            // No duplicate — safe to append atomically (B-06).
            const entry = { id, title, type: typeLabel, uploaded, file: filePath };
            await updateDoc(doc(_dDb, "portfolio", "docs"), { [`data.${typeKey}`]: arrayUnion(entry) });
            setUploadStatus('Uploaded successfully!', 'success');
        }

        // Re-render docs in place
        await renderDocs();
        setTimeout(() => closeDocUploadModal(), 1200);

    } catch (err) {
        console.error('Doc upload error:', err);
        setUploadStatus(`Upload failed: ${err.message || 'Unknown error'}`, 'error');
        if (docUploadSubmit) {
            docUploadSubmit.disabled = false;
            docUploadSubmit.innerHTML = '<i class="fa-solid fa-cloud-arrow-up"></i> Upload';
        }
    }
}

// ── DOC DELETE MODAL ──────────────────────────────────────────

let pendingDeleteDoc = null;

const docDeleteOverlay = document.getElementById('docDeleteOverlay');
const docDeleteClose   = document.getElementById('docDeleteClose');
const docDeleteCancel  = document.getElementById('docDeleteCancel');
const docDeleteConfirm = document.getElementById('docDeleteConfirm');
const docDeleteTitle   = document.getElementById('docDeleteTitle');

function openDocDeleteModal(data) {
    pendingDeleteDoc = data;
    if (docDeleteTitle) {
        docDeleteTitle.textContent = data.title || 'this document';
    }
    if (docDeleteConfirm) {
        docDeleteConfirm.disabled = false;
        docDeleteConfirm.innerHTML = '<i class="fa-solid fa-trash"></i> YES, DELETE';
    }
    if (docDeleteOverlay) docDeleteOverlay.classList.add('open');
}

function closeDocDeleteModal() {
    if (docDeleteOverlay) docDeleteOverlay.classList.remove('open');
    pendingDeleteDoc = null;
}

if (docDeleteClose)  docDeleteClose.addEventListener('click',  closeDocDeleteModal);
if (docDeleteCancel) docDeleteCancel.addEventListener('click', closeDocDeleteModal);
if (docDeleteOverlay) {
    docDeleteOverlay.addEventListener('click', (e) => {
        if (e.target === docDeleteOverlay) closeDocDeleteModal();
    });
}

if (docDeleteConfirm) {
    docDeleteConfirm.addEventListener('click', handleDocDelete);
}

async function handleDocDelete() {
    if (!pendingDeleteDoc) return;

    const { id, file, type, title } = pendingDeleteDoc;

    docDeleteConfirm.disabled = true;
    docDeleteConfirm.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Deleting...';

    try {
        // 1. Remove file from GitHub
        if (file) {
            try {
                await ghDeleteFile(file, `Remove document: ${file}`);
            } catch (ghErr) {
                console.warn('GitHub delete skipped (file may not exist):', ghErr.message);
            }
        }

        // 2. Read Firestore docs — needed to locate the exact object for arrayRemove
        const typeKey = (type || '').toLowerCase() === 'cv' ? 'cv' : 'resume';
        const snap = await getDoc(doc(_dDb, "portfolio", "docs"));
        const json = snap.exists() ? (snap.data().data || {}) : {};
        const arr  = (typeKey === 'cv' ? json.cv : json.resume) || [];

        // 3. B-06: arrayRemove only removes this entry — other tabs' concurrent adds survive
        const entryToRemove = arr.find(e => e.id === id);
        if (entryToRemove) {
            await updateDoc(doc(_dDb, "portfolio", "docs"), { [`data.${typeKey}`]: arrayRemove(entryToRemove) });
        }

        // 5. Close modal and re-render
        closeDocDeleteModal();
        await renderDocs();

    } catch (err) {
        console.error('Doc delete error:', err);
        docDeleteConfirm.disabled = false;
        docDeleteConfirm.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> FAILED';
        setTimeout(() => { docDeleteConfirm.innerHTML = '<i class="fa-solid fa-trash"></i> YES, DELETE'; }, 2000);
    }
}

// ── REACH ME FORM ─────────────────────────────────────────────

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const reachForm   = document.getElementById('reachForm');

let reachBtnResetTimer = null;

function triggerReachInputError(input) {
    const field = input.closest('.reach-field');
    input.classList.remove('input-error');
    if (field) field.classList.remove('shake');
    void input.offsetWidth;
    input.classList.add('input-error');
    if (field) field.classList.add('shake');
    if (field) {
        field.addEventListener('animationend', () => {
            field.classList.remove('shake');
        }, { once: true });
    }
    input.addEventListener('input', () => {
        input.classList.remove('input-error');
    }, { once: true });
}

function triggerReachBtnError(message) {
    const btn = reachForm.querySelector('.reach-btn');
    if (!btn) return;
    if (reachBtnResetTimer) clearTimeout(reachBtnResetTimer);
    btn.classList.remove('btn-error', 'btn-success');
    void btn.offsetWidth;
    btn.classList.add('btn-error');
    btn.innerHTML = `${message} <i class="fa-solid fa-xmark"></i>`;
    reachBtnResetTimer = setTimeout(() => {
        btn.classList.remove('btn-error');
        btn.innerHTML = 'Send Message <i class="fa-solid fa-paper-plane"></i>';
    }, 1800);
}

function triggerReachBtnSuccess() {
    const btn = reachForm.querySelector('.reach-btn');
    if (!btn) return;
    if (reachBtnResetTimer) clearTimeout(reachBtnResetTimer);
    btn.classList.remove('btn-error');
    btn.classList.add('btn-success');
    btn.innerHTML = 'Sent! <i class="fa-solid fa-check"></i>';
    btn.disabled = true;
    reachBtnResetTimer = setTimeout(() => {
        btn.classList.remove('btn-success');
        btn.innerHTML = 'Send Message <i class="fa-solid fa-paper-plane"></i>';
        btn.disabled = false;
        reachForm.reset();
    }, 2500);
}

if (reachForm) {
    reachForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const nameInput    = document.getElementById('r-name');
        const emailInput   = document.getElementById('r-email');
        const subjectInput = document.getElementById('r-subject');
        const msgInput     = document.getElementById('r-message');

        const name    = nameInput.value.trim();
        const email   = emailInput.value.trim();
        const subject = subjectInput.value.trim();
        const message = msgInput.value.trim();

        if (!name)    { triggerReachInputError(nameInput);    triggerReachBtnError('ENTER YOUR NAME');    return; }
        if (!email)   { triggerReachInputError(emailInput);   triggerReachBtnError('ENTER YOUR EMAIL');   return; }
        if (!EMAIL_REGEX.test(email)) { triggerReachInputError(emailInput); triggerReachBtnError('INVALID EMAIL'); return; }
        if (!subject) { triggerReachInputError(subjectInput); triggerReachBtnError('ENTER A SUBJECT');    return; }
        if (!message) { triggerReachInputError(msgInput);     triggerReachBtnError('ENTER YOUR MESSAGE'); return; }

        if (!EMAILJS_SERVICE_ID || !EMAILJS_TEMPLATE_ID || !EMAILJS_PUBLIC_KEY) {
            triggerReachBtnError('EMAIL NOT CONFIGURED');
            return;
        }

        const btn = reachForm.querySelector('.reach-btn');
        btn.disabled = true;
        btn.innerHTML = 'Sending... <i class="fa-solid fa-spinner fa-spin"></i>';

        try {
            await emailjs.send(
                EMAILJS_SERVICE_ID,
                EMAILJS_TEMPLATE_ID,
                { from_name: name, from_email: email, subject, message },
                EMAILJS_PUBLIC_KEY
            );
            triggerReachBtnSuccess();
        } catch (err) {
            console.error('EmailJS error:', err);
            btn.disabled = false;
            triggerReachBtnError('FAILED TO SEND');
        }
    });
}

// ── PROFILE CARD COLLAPSE / EXPAND ───────────────────────────

// ── PROFILE CARD CLONING (B-03 fix) ──────────────────────────
// The canonical profile card lives in #section-about (id="profileCard").
// We clone it into the three placeholder divs for Timeline, Projects, and
// Certificates so there is a single source of truth in the HTML.
// IDs on the clone are remapped so the existing profileCardGroups logic
// below can still find them by their expected IDs.

(function cloneProfileCards() {
    const source = document.getElementById('profileCard');
    if (!source) return;

    const targets = [
        { containerId: 'profileCardTimeline',     newId: 'profileCardTimeline'     },
        { containerId: 'profileCardProjects',      newId: 'profileCardProjects'     },
        { containerId: 'profileCardCertificates',  newId: 'profileCardCertificates' },
    ];

    targets.forEach(({ containerId, newId }) => {
        const container = document.getElementById(containerId);
        if (!container) return;

        const clone = source.cloneNode(true);

        // Give the clone its expected ID and mark it as a clone
        clone.id = newId;
        clone.classList.add('profile-card-clone');

        // Remove the collapse button's unique id (not needed on clones —
        // the querySelectorAll('.profile-card-collapse') in setProfileCardState
        // picks it up by class)
        const collapseBtn = clone.querySelector('.profile-card-collapse');
        if (collapseBtn) {
            collapseBtn.removeAttribute('id');
            collapseBtn.classList.add('profile-card-collapse-clone');
        }

        // Replace the placeholder div's content with the cloned card
        container.replaceWith(clone);
    });
})();

const profileCardGroups = [
    {
        card:      document.getElementById('profileCard'),
        expandBtn: document.getElementById('profileCardExpandBtn'),
        content:   document.getElementById('aboutContent'),
    },
    {
        card:      document.getElementById('profileCardTimeline'),
        expandBtn: document.getElementById('profileCardExpandBtnTimeline'),
        content:   document.getElementById('timelineContent'),
    },
    {
        card:      document.getElementById('profileCardProjects'),
        expandBtn: document.getElementById('profileCardExpandBtnProjects'),
        content:   document.getElementById('projectsContent'),
    },
    {
        card:      document.getElementById('profileCardCertificates'),
        expandBtn: document.getElementById('profileCardExpandBtnCertificates'),
        content:   document.getElementById('certificatesContent'),
    },
];

let profileCardCollapsed = false;

function setProfileCardState(collapsed) {
    profileCardCollapsed = collapsed;
    profileCardGroups.forEach(({ card, expandBtn, content }) => {
        if (!card) return;
        if (collapsed) {
            card.classList.add('collapsed');
            if (expandBtn) expandBtn.classList.add('visible');
            if (content)   content.classList.add('card-hidden');
        } else {
            card.classList.remove('collapsed');
            if (expandBtn) expandBtn.classList.remove('visible');
            if (content)   content.classList.remove('card-hidden');
        }
    });
}

document.querySelectorAll('.profile-card-collapse').forEach(btn => {
    btn.addEventListener('click', () => setProfileCardState(true));
});

document.querySelectorAll('.profile-card-expand-btn').forEach(btn => {
    btn.addEventListener('click', () => setProfileCardState(false));
});

// ── REAL-TIME AGE ─────────────────────────────────────────────

const DOB = new Date('2006-12-15T00:00:00');

function calcAge() {
    const now   = new Date();
    let years   = now.getFullYear() - DOB.getFullYear();
    let months  = now.getMonth()    - DOB.getMonth();
    let days    = now.getDate()     - DOB.getDate();

    if (days < 0) {
        months--;
        const prevMonth = new Date(now.getFullYear(), now.getMonth(), 0);
        days += prevMonth.getDate();
    }
    if (months < 0) {
        years--;
        months += 12;
    }

    return { years, months, days };
}

function updateAge() {
    const el = document.getElementById('aboutAge');
    if (!el) return;
    const { years, months, days } = calcAge();
    el.innerHTML =
        `<span class="age-num">${years}</span> years, ` +
        `<span class="age-num">${months}</span> ${months === 1 ? 'month' : 'months'}, and ` +
        `<span class="age-num">${days}</span> ${days === 1 ? 'day' : 'days'}`;
}

updateAge();
setInterval(updateAge, 1000 * 60);

// ── STAT CARDS ────────────────────────────────────────────────

function populateStats() {
    const projectCount = FETCHED_PROJECTS.length;
    const certCount    = FETCHED_CERTS.length;
    // Q-05: derive startYear from data instead of hardcoding — prevents silent drift each year.
    // Falls back to current year if no data exists (yearsExp will be 0).
    const allYears = [
        ...FETCHED_TIMELINE.map(e => e.date ? parseInt(e.date.split('-')[0]) : null),
        ...FETCHED_MILESTONES.map(e => e.date ? parseInt(e.date.split('-').pop()) : null),
    ].filter(y => y && !isNaN(y));
    const startYear    = allYears.length > 0 ? Math.min(...allYears) : new Date().getFullYear();
    const yearsExp     = new Date().getFullYear() - startYear;
    const langCount    = (FETCHED_ABOUT.proficiency || []).length;

    const setValue = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val;
    };

    setValue('statProjects', projectCount);
    setValue('statCerts',    certCount);
    setValue('statYears',    yearsExp);
    setValue('statLangs',    langCount);
}

document.querySelectorAll('.about-stat-card[data-goto]').forEach(card => {
    card.addEventListener('click', () => {
        const target = card.dataset.goto;
        if (target) switchSection(target);
    });
});

// ── RENDER SKILLS ─────────────────────────────────────────────

function renderSkills() {
    const barsEl   = document.getElementById('skillsBars');
    const legendEl = document.getElementById('skillsLegend');
    if (!barsEl || !legendEl) return;

    barsEl.innerHTML = '';

    const proficiency = FETCHED_ABOUT.proficiency || [];

    if (proficiency.length === 0) {
        barsEl.innerHTML = `
            <div style="text-align:center;padding:32px 0;color:rgba(255,255,255,0.2);">
                <i class="fa-solid fa-code" style="font-size:28px;margin-bottom:10px;display:block;"></i>
                No listed language
            </div>
        `;
        if (legendEl) legendEl.style.display = 'none';
        return;
    }

    if (legendEl) legendEl.style.display = '';

    proficiency.forEach((entry, i) => {
        const langMeta  = FETCHED_LANGS.find(l => l.name === entry.language) || {};
        const levelMeta = LEVEL_DATA[entry.level] || LEVEL_DATA[0];
        const pct       = (entry.level / 5) * 100;

        const row = document.createElement('div');
        row.className = 'skills-bar-row';
        row.innerHTML = `
            <div class="skills-bar-meta">
                <div class="skills-bar-left">
                    <i class="${langMeta.icon || 'fa-solid fa-code'} skills-bar-icon" style="color:${langMeta.color || '#fff'};"></i>
                    <span class="skills-bar-name">${entry.language}</span>
                </div>
                <span class="skills-bar-level">${levelMeta.level}</span>
            </div>
            <div class="skills-bar-track">
                <div class="skills-bar-fill"
                     style="--bar-w:${pct}%; background:${langMeta.color || levelMeta.color}; transition-delay:${i * 0.1}s;"></div>
            </div>
        `;

        barsEl.appendChild(row);
    });

    legendEl.innerHTML = `<div class="skills-legend-title">LEGEND</div>`;
    LEVEL_DATA.forEach(lvl => {
        const item = document.createElement('div');
        item.className = 'skills-legend-item';
        item.innerHTML = `
            <div class="skills-legend-dot" style="background:${lvl.color};"></div>
            <span class="skills-legend-label">${lvl.level}</span>
        `;
        legendEl.appendChild(item);
    });
    // Q-04: use appendChild instead of innerHTML += to avoid re-parsing the entire subtree
    const hint = document.createElement('div');
    hint.className = 'skills-legend-hint';
    hint.textContent = 'CLICK FOR DETAILS';
    legendEl.appendChild(hint);

    const modalContent = document.getElementById('levelsModalContent');
    if (modalContent) {
        modalContent.innerHTML = '';
        LEVEL_DATA.forEach(lvl => {
            const item = document.createElement('div');
            item.className = 'level-item';
            item.innerHTML = `
                <div class="level-item-dot" style="background:${lvl.color};"></div>
                <div class="level-item-body">
                    <div class="level-item-name" style="color:${lvl.color};">${lvl.level}</div>
                    <div class="level-item-desc">${lvl.desc}</div>
                </div>
            `;
            modalContent.appendChild(item);
        });
    }
}

// ── RENDER ABOUT ──────────────────────────────────────────────

function renderAbout() {
    // BIO
    const bioEl = document.getElementById('aboutBio');
    if (bioEl) {
        if (FETCHED_ABOUT.bio?.text) {
            bioEl.textContent = FETCHED_ABOUT.bio.text;
        } else {
            bioEl.innerHTML = `<i class="fa-regular fa-file-lines" style="margin-right:8px;color:rgba(255,255,255,0.2);"></i><span style="color:rgba(255,255,255,0.2);font-style:italic;">No Bio</span>`;
        }
    }

    // EDUCATION 
    const eduList = document.getElementById('aboutEduList');
    if (eduList) {
        const eduArr = Array.isArray(FETCHED_ABOUT.education)
            ? FETCHED_ABOUT.education
            : (FETCHED_ABOUT.education?.course ? [FETCHED_ABOUT.education] : []);

        eduList.innerHTML = '';

        if (eduArr.length === 0) {
            eduList.innerHTML = `
                <div style="text-align:center;padding:32px 0;color:rgba(255,255,255,0.2);">
                    <i class="fa-solid fa-graduation-cap" style="font-size:28px;margin-bottom:10px;display:block;"></i>
                    No listed education
                </div>`;
        } else {
            function parseStoredDate(val) {
                if (!val) return null;
                const [mm, dd, yyyy] = val.split('-');
                if (!mm || !dd || !yyyy) return null;
                return new Date(`${yyyy}-${mm}-${dd}`);
            }

            eduArr.forEach((edu, idx) => {
                const card = document.createElement('div');
                card.className = 'about-edu-card';
                card.style.marginBottom = idx < eduArr.length - 1 ? '10px' : '';

                const now       = new Date();
                const endDate   = parseStoredDate(edu.schoolEnd);
                const startDate = parseStoredDate(edu.schoolStart);
                const fmt       = d => d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
                const isOngoing = !endDate || endDate > now;
                const dateStr   = isOngoing
                    ? `${startDate ? fmt(startDate) : ''} — present`
                    : `Graduated: ${endDate.getFullYear()}`;
                const yearStr   = edu.year || '';
                const detailStr = yearStr ? `${yearStr} · ${dateStr}` : dateStr;

                card.innerHTML = `
                    <div class="about-edu-icon"><i class="fa-solid fa-graduation-cap"></i></div>
                    <div class="about-edu-text">
                        <div class="about-edu-degree">${edu.course || ''}</div>
                        <div class="about-edu-school">${edu.school || ''}</div>
                        <div class="about-edu-detail">${detailStr}</div>
                    </div>
                `;

                card.dataset.eduIdx = idx;
                eduList.appendChild(card);
            });
        }

        if (isEditMode) _injectEduDeleteBtns();
    }

    // SKILLS
    skillsAnimated = false;
    renderSkills();

    if (currentSection === 'about') {
        setTimeout(() => {
            const barsEl = document.getElementById('skillsBars');
            if (barsEl) barsEl.classList.add('animated');
            skillsAnimated = true;
        }, 100);
    }
}



const levelsOverlay = document.getElementById('levelsOverlay');
const levelsClose   = document.getElementById('levelsClose');
const skillsLegend  = document.getElementById('skillsLegend');

if (skillsLegend) {
    skillsLegend.addEventListener('click', () => {
        if (levelsOverlay) levelsOverlay.classList.add('open');
    });
}

if (levelsClose) {
    levelsClose.addEventListener('click', () => levelsOverlay.classList.remove('open'));
}

if (levelsOverlay) {
    levelsOverlay.addEventListener('click', (e) => {
        if (e.target === levelsOverlay) levelsOverlay.classList.remove('open');
    });
}

// ── RENDER CERTIFICATES ───────────────────────────────────────

function renderCertCard(data, companyLabel = null) {
    const card = document.createElement('div');
    card.className = 'cert-card';
    if (data.id) card.dataset.certId = data.id;

    const rawUrl = data.file
        ? `https://raw.githubusercontent.com/devssst/my-portfolio/main/${data.file.split('/').map(encodeURIComponent).join('/')}`
        : null;

    let dateStr = '';
    if (data.date) {
        const parts = data.date.split('-');
        if (parts.length === 3) {
            const d = new Date(parseInt(parts[2]), parseInt(parts[0]) - 1, parseInt(parts[1]));
            dateStr = d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
        } else if (parts.length === 2) {
            const d = new Date(data.date + '-01');
            dateStr = d.toLocaleDateString('en-US', { year: 'numeric', month: 'short' });
        }
    }

    const previewHTML = rawUrl
        ? `<img src="${rawUrl}" alt="${data.title}" loading="lazy">`
        : `<i class="fa-solid fa-certificate cert-card-placeholder-icon"></i>`;

    // Solo cards get company name overlaid on the banner bottom-left
    const companyOverlayHTML = companyLabel
        ? `<div class="cert-card-company-overlay">${companyLabel.toUpperCase()}</div>`
        : '';

    card.innerHTML = `
        <button class="cert-card-delete" title="Delete certificate" aria-label="Delete certificate">
            <i class="fa-solid fa-xmark"></i>
        </button>
        <div class="cert-card-preview">
            ${previewHTML}
            ${companyOverlayHTML}
        </div>
        <div class="cert-card-body">
            <div class="cert-card-title">${sanitize(data.title)}</div>
            ${data.details ? `<div class="cert-card-details">${sanitize(data.details)}</div>` : ''}
            ${dateStr ? `<div class="cert-card-date">${dateStr}</div>` : ''}
        </div>
    `;

    const img = card.querySelector('.cert-card-preview img');
    if (img) {
        img.addEventListener('error', () => {
            img.replaceWith(Object.assign(
                document.createElement('i'),
                { className: 'fa-solid fa-certificate cert-card-placeholder-icon' }
            ));
        });
    }

    const deleteBtn = card.querySelector('.cert-card-delete');
    if (deleteBtn) {
        deleteBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            openCertDeleteModal(data);
        });
    }

    card.addEventListener('click', (e) => {
        if (e.target.closest('.cert-card-delete')) return;
        const overlay    = document.getElementById('certOverlay');
        const overlayImg = document.getElementById('certOverlayImg');
        if (!overlay || !overlayImg || !rawUrl) return;
        overlayImg.src = rawUrl;
        overlayImg.alt = data.title;
        overlay.classList.add('open');
    });

    return card;
}

function renderCerts() {
    const root = document.getElementById('certsRoot');
    if (!root) return;

    if (!FETCHED_CERTS || FETCHED_CERTS.length === 0) {
        root.innerHTML = `
            <div style="text-align:center;padding:40px 0;color:rgba(255,255,255,0.2);width:100%;">
                <i class="fa-solid fa-certificate" style="font-size:32px;margin-bottom:10px;display:block;"></i>
                No certificates yet.
            </div>
        `;
        return;
    }

    const companies = [];
    FETCHED_CERTS.forEach(cert => {
        const c = (cert.company || '').trim() || 'Unknown';
        if (!companies.includes(c)) companies.push(c);
    });
    companies.sort((a, b) => a === 'Unknown' ? 1 : b === 'Unknown' ? -1 : a.localeCompare(b));

    // Split into solo (1 cert) and multi (2+ certs)
    const soloCompanies = companies.filter(c =>
        FETCHED_CERTS.filter(cert => ((cert.company || '').trim() || 'Unknown') === c).length === 1
    );
    const multiCompanies = companies.filter(c =>
        FETCHED_CERTS.filter(cert => ((cert.company || '').trim() || 'Unknown') === c).length > 1
    );

    root.innerHTML = '';

    // ── SOLO SECTION ─────────────────────────
    if (soloCompanies.length > 0) {
        const soloSection = document.createElement('div');
        soloSection.className = 'certs-solo-section';

        const grid = document.createElement('div');
        grid.className = 'certs-grid';

        soloCompanies.forEach(company => {
            const cert = FETCHED_CERTS.find(c => ((c.company || '').trim() || 'Unknown') === company);
            if (cert) grid.appendChild(renderCertCard(cert, company));
        });

        soloSection.appendChild(grid);
        root.appendChild(soloSection);
    }

    // ── MULTI SECTION ─────────────────────────
    multiCompanies.forEach(company => {
        const group = FETCHED_CERTS.filter(c =>
            ((c.company || '').trim() || 'Unknown') === company
        );
        if (group.length === 0) return;

        const groupEl = document.createElement('div');
        groupEl.className = 'certs-company-group';
        groupEl.innerHTML = `<div class="certs-company-label">${company.toUpperCase()}</div>`;

        const grid = document.createElement('div');
        grid.className = 'certs-grid';
        group.forEach(cert => grid.appendChild(renderCertCard(cert, null)));
        groupEl.appendChild(grid);
        root.appendChild(groupEl);
    });
}

// ── CERT OVERLAY ──────────────────────────────────────────────

const certOverlay      = document.getElementById('certOverlay');
const certOverlayClose = document.getElementById('certOverlayClose');

if (certOverlayClose) {
    certOverlayClose.addEventListener('click', () => certOverlay.classList.remove('open'));
}

if (certOverlay) {
    certOverlay.addEventListener('click', (e) => {
        if (e.target === certOverlay) certOverlay.classList.remove('open');
    });
}

// ── CERT UPLOAD MODAL ─────────────────────────────────────────

let selectedCertFile = null;

const certUploadOverlay  = document.getElementById('certUploadOverlay');
const certUploadClose    = document.getElementById('certUploadClose');
const certDropZone       = document.getElementById('certDropZone');
const certFileInput      = document.getElementById('certFileInput');
const certDropBrowse     = document.getElementById('certDropBrowse');
const certDropFileName   = document.getElementById('certDropFileName');
const certTitleInput     = document.getElementById('certTitleInput');
const certDetailsInput   = document.getElementById('certDetailsInput');
const certCompanyInput   = document.getElementById('certCompanyInput');
const certDateInput      = document.getElementById('certDateInput');
const certUploadSubmit   = document.getElementById('certUploadSubmit');
const certUploadStatus   = document.getElementById('certUploadStatus');

function openCertUploadModal() {
    resetCertUploadModal();
    if (certUploadOverlay) certUploadOverlay.classList.add('open');
}

function closeCertUploadModal() {
    if (certUploadOverlay) certUploadOverlay.classList.remove('open');
}

function resetCertUploadModal() {
    selectedCertFile = null;
    if (certDropZone)     certDropZone.classList.remove('drag-over', 'has-file');
    if (certDropFileName) { certDropFileName.textContent = 'No file selected'; certDropFileName.classList.remove('has-file'); }
    if (certTitleInput)   certTitleInput.value   = '';
    if (certDetailsInput) certDetailsInput.value = '';
    if (certCompanyInput) certCompanyInput.value = '';
    if (certDateInput)    certDateInput.value    = '';
    if (certFileInput)    certFileInput.value    = '';
    if (certUploadStatus) { certUploadStatus.textContent = ''; certUploadStatus.className = 'doc-upload-status'; }
    if (certUploadSubmit) { certUploadSubmit.disabled = false; certUploadSubmit.innerHTML = '<i class="fa-solid fa-cloud-arrow-up"></i> Upload'; }
}

function setCertUploadStatus(msg, type) {
    if (!certUploadStatus) return;
    certUploadStatus.textContent = msg;
    certUploadStatus.className   = 'doc-upload-status' + (type ? ` ${type}` : '');
}

function handleCertFileSelected(file) {
    if (!file) return;
    const allowed = ['image/png', 'image/jpeg', 'image/webp', 'image/jpg'];
    if (!allowed.includes(file.type)) {
        setCertUploadStatus('Only PNG, JPG, or WEBP images are accepted.', 'error');
        return;
    }
    selectedCertFile = file;
    if (certDropZone)     certDropZone.classList.add('has-file');
    if (certDropFileName) { certDropFileName.textContent = file.name; certDropFileName.classList.add('has-file'); }
    if (certTitleInput && !certTitleInput.value) {
        certTitleInput.value = file.name.replace(/\.[^/.]+$/, '').replace(/[-_]/g, ' ');
    }
    setCertUploadStatus('', '');
}

if (certUploadClose) certUploadClose.addEventListener('click', closeCertUploadModal);
if (certUploadOverlay) {
    certUploadOverlay.addEventListener('click', (e) => {
        if (e.target === certUploadOverlay) closeCertUploadModal();
    });
}

if (certDropBrowse) {
    certDropBrowse.addEventListener('click', (e) => {
        e.stopPropagation();
        if (certFileInput) certFileInput.click();
    });
}

if (certDropZone) {
    certDropZone.addEventListener('click', (e) => {
        if (e.target === certDropBrowse || e.target.closest('.doc-drop-browse')) return;
        if (certFileInput) certFileInput.click();
    });
    certDropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        certDropZone.classList.add('drag-over');
    });
    certDropZone.addEventListener('dragleave', (e) => {
        if (!certDropZone.contains(e.relatedTarget)) certDropZone.classList.remove('drag-over');
    });
    certDropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        certDropZone.classList.remove('drag-over');
        const file = e.dataTransfer?.files?.[0] || null;
        if (file) handleCertFileSelected(file);
    });
}

if (certFileInput) {
    certFileInput.addEventListener('change', () => {
        if (certFileInput.files?.[0]) handleCertFileSelected(certFileInput.files[0]);
    });
}

if (certUploadSubmit) certUploadSubmit.addEventListener('click', handleCertUpload);

async function handleCertUpload() {
    if (!selectedCertFile) {
        setCertUploadStatus('Please select an image file first.', 'error');
        return;
    }
    const title   = certTitleInput?.value.trim()   || '';
    const details = certDetailsInput?.value.trim() || '';
    const company = certCompanyInput?.value.trim() || '';
    const dateRaw = certDateInput?.value || '';

    let date = '';
    if (dateRaw) {
        const [yyyy, mm, dd] = dateRaw.split('-');
        if (yyyy && mm && dd) date = `${mm}-${dd}-${yyyy}`;
    }

    if (!title) {
        setCertUploadStatus('Please enter a title.', 'error');
        if (certTitleInput) certTitleInput.focus();
        return;
    }
    if (!GH_TOKEN || !GH_OWNER || !GH_REPO) {
        setCertUploadStatus('GitHub credentials not loaded. Try again.', 'error');
        return;
    }

    certUploadSubmit.disabled = true;
    certUploadSubmit.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Uploading...';
    setCertUploadStatus('', '');

    try {
        const id           = `cert-${Date.now()}`;
        const rawFileName  = selectedCertFile.name;
        // FIX: sanitize filename — replace spaces and unsafe chars before building path
        const fileName     = rawFileName.replace(/\s+/g, '-').replace(/[^a-zA-Z0-9._-]/g, '');
        const filePath     = `data/files/${fileName}`;

        const base64 = await new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload  = () => resolve(reader.result.split(',')[1]);
            reader.onerror = reject;
            reader.readAsDataURL(selectedCertFile);
        });

        setCertUploadStatus('Pushing to GitHub...', '');
        // FIX: fetch existing SHA so re-uploading same filename works
        const certExistingSha = await ghGetSHA(filePath);
        await ghPushFile(filePath, base64, `Add certificate: ${fileName}`, certExistingSha);

        setCertUploadStatus('Saving to Firestore...', '');

        // B-07: Check FETCHED_CERTS for an existing entry with the same filePath.
        // FETCHED_CERTS is kept in sync, so this avoids an extra Firestore read
        // in the common case (new file). Only reads Firestore when a duplicate is found.
        const existingCert = FETCHED_CERTS.find(c => c.file === filePath);

        if (existingCert) {
            // Same filename already has a metadata entry — update it in place,
            // preserving its original id so no existing references break.
            const certsSnap = await getDoc(doc(_dDb, "portfolio", "certs"));
            const raw       = certsSnap.exists() ? certsSnap.data().data : null;
            const certsArr  = Array.isArray(raw) ? raw : (raw?.certificates || []);
            const updated   = certsArr.map(c =>
                c.file === filePath ? { ...c, title, details, company, date } : c
            );
            await updateDoc(doc(_dDb, "portfolio", "certs"), { data: updated });
            FETCHED_CERTS = updated;
            setCertUploadStatus('Certificate replaced — existing entry updated.', 'success');
        } else {
            // No duplicate — safe to append atomically (B-06).
            const entry = { id, title, details, company, date, file: filePath };
            await updateDoc(doc(_dDb, "portfolio", "certs"), { data: arrayUnion(entry) });
            FETCHED_CERTS = [...FETCHED_CERTS, entry];
            setCertUploadStatus('Certificate uploaded!', 'success');
        }
        renderCerts();
        renderTimeline();
        populateStats();
        if (isEditMode) {
            injectCertAddBtn();
            document.getElementById('certsRoot')?.classList.add('edit-active');
        }
        setTimeout(() => closeCertUploadModal(), 1200);

    } catch (err) {
        console.error('Cert upload error:', err);
        setCertUploadStatus(`Upload failed: ${err.message || 'Unknown error'}`, 'error');
        certUploadSubmit.disabled = false;
        certUploadSubmit.innerHTML = '<i class="fa-solid fa-cloud-arrow-up"></i> Upload';
    }
}

// ── CERT DELETE MODAL ─────────────────────────────────────────

let pendingDeleteCert = null;

const certDeleteOverlay = document.getElementById('certDeleteOverlay');
const certDeleteClose   = document.getElementById('certDeleteClose');
const certDeleteCancel  = document.getElementById('certDeleteCancel');
const certDeleteConfirm = document.getElementById('certDeleteConfirm');
const certDeleteTitle   = document.getElementById('certDeleteTitle');

function openCertDeleteModal(data) {
    pendingDeleteCert = data;
    if (certDeleteTitle) certDeleteTitle.textContent = data.title || 'this certificate';
    if (certDeleteConfirm) {
        certDeleteConfirm.disabled = false;
        certDeleteConfirm.innerHTML = '<i class="fa-solid fa-trash"></i> YES, DELETE';
    }
    if (certDeleteOverlay) certDeleteOverlay.classList.add('open');
}

function closeCertDeleteModal() {
    if (certDeleteOverlay) certDeleteOverlay.classList.remove('open');
    pendingDeleteCert = null;
}

if (certDeleteClose)  certDeleteClose?.addEventListener('click',  closeCertDeleteModal);
if (certDeleteCancel) certDeleteCancel?.addEventListener('click', closeCertDeleteModal);
if (certDeleteOverlay) {
    certDeleteOverlay.addEventListener('click', (e) => {
        if (e.target === certDeleteOverlay) closeCertDeleteModal();
    });
}
if (certDeleteConfirm) certDeleteConfirm.addEventListener('click', handleCertDelete);

async function handleCertDelete() {
    if (!pendingDeleteCert) return;
    const { id, file } = pendingDeleteCert;

    certDeleteConfirm.disabled = true;
    certDeleteConfirm.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Deleting...';

    try {
        if (file) {
            try {
                await ghDeleteFile(file, `Remove certificate: ${file}`);
            } catch (ghErr) {
                console.warn('GitHub cert delete skipped:', ghErr.message);
            }
        }

        const snap  = await getDoc(doc(_dDb, "portfolio", "certs"));
        const raw   = snap.exists() ? snap.data().data : null;
        const certs = Array.isArray(raw) ? raw : (raw?.certificates || []);
        // B-06: arrayRemove only removes this entry — other tabs' concurrent adds survive
        const certToRemove = certs.find(c => c.id === id);
        if (certToRemove) {
            await updateDoc(doc(_dDb, "portfolio", "certs"), { data: arrayRemove(certToRemove) });
        }

        FETCHED_CERTS = FETCHED_CERTS.filter(c => c.id !== id);
        closeCertDeleteModal();
        renderCerts();
        renderTimeline();
        populateStats();
        if (isEditMode) {
            injectCertAddBtn();
            document.getElementById('certsRoot')?.classList.add('edit-active');
        }

    } catch (err) {
        console.error('Cert delete error:', err);
        certDeleteConfirm.disabled = false;
        certDeleteConfirm.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> FAILED';
        setTimeout(() => { certDeleteConfirm.innerHTML = '<i class="fa-solid fa-trash"></i> YES, DELETE'; }, 2000);
    }
}

// ── ABOUT EDIT BTN VISIBILITY ─────────────────────────────────

function updateAboutEditBtnVisibility() {
    const btn = document.getElementById('aboutEditBtn');
    if (!btn) return;
    if (isEditMode && currentSection === 'about') {
        btn.classList.add('visible');
    } else {
        btn.classList.remove('visible');
    }
}

// ── ABOUT EDIT MODAL ──────────────────────────────────────────

const aboutEditOverlay    = document.getElementById('aboutEditOverlay');
const aboutEditClose      = document.getElementById('aboutEditClose');
const aboutEditCancel     = document.getElementById('aboutEditCancel');
const aboutEditSave       = document.getElementById('aboutEditSave');
const aboutEditStatus     = document.getElementById('aboutEditStatus');
const aboutBioInput       = document.getElementById('aboutBioInput');
const aboutLangSearch     = document.getElementById('aboutLangSearch');
const aboutLangDropdown   = document.getElementById('aboutLangDropdown');
const aboutLangAddBtn     = document.getElementById('aboutLangAddBtn');
const aboutLangStaged     = document.getElementById('aboutLangStaged');
const aboutEditBtn        = document.getElementById('aboutEditBtn');
const aboutLevelSelect    = document.getElementById('aboutLevelSelect');
const aboutEduAddBtn      = document.getElementById('aboutEduAddBtn');
const eduEntriesList      = document.getElementById('eduEntriesList');

let   eduDeleteTargetIdx      = -1;
const aboutEduDeleteOverlay   = document.getElementById('aboutEduDeleteOverlay');
const aboutEduDeleteClose     = document.getElementById('aboutEduDeleteClose');
const aboutEduDeleteCancel    = document.getElementById('aboutEduDeleteCancel');
const aboutEduDeleteConfirm   = document.getElementById('aboutEduDeleteConfirm');

let stagedLangs  = [];
let stagedEdu    = [];
// B-09: true whenever the about edit modal has unsaved changes
let _aboutDirty  = false;

// ── ABOUT EDIT — OPEN / CLOSE ─────────────────────────────────

function openAboutEditModal() {
    // Pre-populate BIO
    if (aboutBioInput) {
        aboutBioInput.value = FETCHED_ABOUT.bio?.text || '';
    }

    // Pre-populate EDUCATION
    const rawEdu = FETCHED_ABOUT.education;
    if (Array.isArray(rawEdu)) {
        stagedEdu = rawEdu.map(e => ({ ...e }));
    } else if (rawEdu?.course) {
        stagedEdu = [{ ...rawEdu }];
    } else {
        stagedEdu = [];
    }
    renderStagedEdu();

    // Pre-populate PROFICIENCY from current FETCHED_ABOUT
    stagedLangs = (FETCHED_ABOUT.proficiency || []).map(e => ({ ...e }));
    renderStagedLangs();

    if (aboutLangSearch)   aboutLangSearch.value = '';
    if (aboutLangDropdown) aboutLangDropdown.classList.remove('open');
    if (aboutEditStatus)   { aboutEditStatus.textContent = ''; aboutEditStatus.className = 'about-edit-status'; }
    if (aboutEditSave)     { aboutEditSave.disabled = false; aboutEditSave.innerHTML = '<i class="fa-solid fa-floppy-disk"></i> SAVE'; }

    if (aboutEditOverlay) aboutEditOverlay.classList.add('open');
    // B-09: reset dirty flag — opening always starts from a clean snapshot
    _aboutDirty = false;
}

function closeAboutEditModal() {
    if (aboutEditOverlay) aboutEditOverlay.classList.remove('open');
    // B-09: cancelled or closed = staged changes discarded = no longer dirty
    _aboutDirty = false;
}

if (aboutEditBtn)     aboutEditBtn.addEventListener('click', openAboutEditModal);
if (aboutEditClose)   aboutEditClose.addEventListener('click', closeAboutEditModal);
if (aboutEditCancel)  aboutEditCancel.addEventListener('click', closeAboutEditModal);
// B-09: mark dirty on any field change inside the about modal
if (aboutBioInput)    aboutBioInput.addEventListener('input', () => { _aboutDirty = true; });
if (aboutEditOverlay) {
    aboutEditOverlay.addEventListener('click', (e) => {
        if (e.target !== aboutEditOverlay) return;
        const focused = document.activeElement;
        const isFieldFocused = focused && (
            focused.tagName === 'INPUT' ||
            focused.tagName === 'TEXTAREA' ||
            focused.tagName === 'SELECT'
        );
        if (isFieldFocused) return;
        closeAboutEditModal();
    });
}

// ── ABOUT EDIT — LANGUAGE PICKER ─────────────────────────────

function renderLangDropdown(query) {
    if (!aboutLangDropdown) return;
    const q        = (query || '').toLowerCase().trim();
    const filtered = FETCHED_LANGS.filter(l => l.name.toLowerCase().includes(q));

    if (filtered.length === 0) {
        aboutLangDropdown.innerHTML = `<div class="about-lang-no-results">No results</div>`;
        aboutLangDropdown.classList.add('open');
        return;
    }

    aboutLangDropdown.innerHTML = '';
    filtered.forEach(lang => {
        const alreadyStaged = stagedLangs.some(s => s.language === lang.name);
        const item = document.createElement('div');
        item.className = 'about-lang-item' + (alreadyStaged ? ' disabled' : '');
        item.innerHTML = `
            <i class="${lang.icon}" style="color:${lang.color}; font-size:14px; width:16px; text-align:center;"></i>
            ${lang.name}
        `;
        if (!alreadyStaged) {
            item.addEventListener('click', () => {
                if (aboutLangSearch)  aboutLangSearch.value = lang.name;
                aboutLangDropdown.classList.remove('open');
            });
        }
        aboutLangDropdown.appendChild(item);
    });

    aboutLangDropdown.classList.add('open');
}

if (aboutLangSearch) {
    aboutLangSearch.addEventListener('input', () => {
        renderLangDropdown(aboutLangSearch.value);
    });
    aboutLangSearch.addEventListener('focus', () => {
        renderLangDropdown(aboutLangSearch.value);
    });
}

document.addEventListener('click', (e) => {
    if (aboutLangDropdown && aboutLangSearch && !aboutLangSearch.contains(e.target) && !aboutLangDropdown.contains(e.target)) {
        aboutLangDropdown.classList.remove('open');
    }
});

// ── ABOUT EDIT — STAGED LANGS RENDER ─────────────────────────

function renderStagedLangs() {
    if (!aboutLangStaged) return;
    aboutLangStaged.innerHTML = '';
    stagedLangs.forEach((entry, idx) => {
        const levelMeta = LEVEL_DATA[entry.level] || LEVEL_DATA[0];
        const row       = document.createElement('div');
        row.className   = 'about-lang-staged-row';
        row.innerHTML   = `
            <span class="about-lang-staged-name">${entry.language}</span>
            <span class="about-lang-staged-level" style="color:${levelMeta.color};">${levelMeta.level}</span>
            <button type="button" class="about-lang-staged-remove" title="Remove">
                <i class="fa-solid fa-xmark"></i>
            </button>
        `;
        row.querySelector('.about-lang-staged-remove').addEventListener('click', () => {
            stagedLangs.splice(idx, 1);
            _aboutDirty = true; // B-09
            renderStagedLangs();
        });
        aboutLangStaged.appendChild(row);
    });
}

// ── ABOUT EDIT — EDUCATION ENTRIES ───────────────────────────

function toInputDate(stored) {
    if (!stored) return '';
    const [mm, dd, yyyy] = stored.split('-');
    if (!mm || !dd || !yyyy) return '';
    return `${yyyy}-${mm}-${dd}`;
}

function fromInputDate(val) {
    if (!val) return '';
    const [yyyy, mm, dd] = val.split('-');
    if (!yyyy || !mm || !dd) return '';
    return `${mm}-${dd}-${yyyy}`;
}

function renderStagedEdu() {
    if (!eduEntriesList) return;
    eduEntriesList.innerHTML = '';

    if (stagedEdu.length === 0) {
        eduEntriesList.innerHTML = `
            <div style="text-align:center;padding:16px 0 4px;color:rgba(255,255,255,0.2);font-size:12px;">
                No education entries yet.
            </div>`;
        return;
    }

    stagedEdu.forEach((edu, idx) => {
        const block = document.createElement('div');
        block.className = 'edu-entry-block';
        // B-08: Values are assigned via .value below — NOT interpolated into innerHTML.
        // Interpolating user data into value="..." breaks on double-quotes and can
        // inject unexpected HTML. Separating structure from data is the safe pattern.
        block.innerHTML = `
            <div class="edu-entry-block-header">
                <span class="edu-entry-block-num">ENTRY ${idx + 1}</span>
                <button type="button" class="edu-entry-remove-btn" title="Remove entry">
                    <i class="fa-solid fa-xmark"></i>
                </button>
            </div>
            <div class="about-edit-field">
                <label>COURSE</label>
                <input type="text" class="edu-f-course" value=""
                    placeholder="e.g. Bachelor of Science in Information Technology" autocomplete="off">
            </div>
            <div class="about-edit-field">
                <label>SCHOOL</label>
                <input type="text" class="edu-f-school" value=""
                    placeholder="e.g. Dalubhasaang Politekniko ng Lungsod ng Baliwag" autocomplete="off">
            </div>
            <div class="about-edit-field-row">
                <div class="about-edit-field">
                    <label>START</label>
                    <input type="date" class="edu-f-start" value="">
                </div>
                <div class="about-edit-field">
                    <label>END</label>
                    <input type="date" class="edu-f-end" value="">
                </div>
            </div>
            <div class="about-edit-field">
                <label>CURRENT YEAR</label>
                <input type="text" class="edu-f-year" value=""
                    placeholder="e.g. 1st Year, 2nd Year, ..." autocomplete="off">
            </div>
        `;
        // B-08: Assign values directly on the DOM elements — fully safe against quote injection.
        block.querySelector('.edu-f-course').value = edu.course      || '';
        block.querySelector('.edu-f-school').value = edu.school      || '';
        block.querySelector('.edu-f-start').value  = toInputDate(edu.schoolStart);
        block.querySelector('.edu-f-end').value    = toInputDate(edu.schoolEnd);
        block.querySelector('.edu-f-year').value   = edu.year        || '';

        block.querySelector('.edu-entry-remove-btn').addEventListener('click', () => {
            stagedEdu.splice(idx, 1);
            _aboutDirty = true; // B-09
            renderStagedEdu();
        });

        // Live-sync inputs back into stagedEdu so values survive re-renders
        ['course','school','year'].forEach(field => {
            block.querySelector(`.edu-f-${field}`).addEventListener('input', e => {
                // FIX: was a redundant ternary — field is already the key
                stagedEdu[idx][field] = e.target.value;
                _aboutDirty = true; // B-09
            });
        });
        block.querySelector('.edu-f-start').addEventListener('change', e => {
            stagedEdu[idx].schoolStart = fromInputDate(e.target.value);
            _aboutDirty = true; // B-09
        });
        block.querySelector('.edu-f-end').addEventListener('change', e => {
            stagedEdu[idx].schoolEnd = fromInputDate(e.target.value);
            _aboutDirty = true; // B-09
        });

        eduEntriesList.appendChild(block);
    });
}

if (aboutEduAddBtn) {
    aboutEduAddBtn.addEventListener('click', () => {
        stagedEdu.push({ course: '', school: '', schoolStart: '', schoolEnd: '', year: '' });
        _aboutDirty = true; // B-09
        renderStagedEdu();
        if (eduEntriesList) {
            const last = eduEntriesList.lastElementChild;
            if (last) last.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
    });
}

// ── ABOUT EDIT — ADD LANGUAGE ─────────────────────────────────

if (aboutLangAddBtn) {
    aboutLangAddBtn.addEventListener('click', () => {
        const name = (aboutLangSearch?.value || '').trim();
        if (!name) return;

        const levelIdx = parseInt(aboutLevelSelect?.value || '0', 10);
        const catalog  = FETCHED_LANGS.find(l => l.name.toLowerCase() === name.toLowerCase());
        const resolved = catalog ? catalog.name : name;

        if (stagedLangs.some(s => s.language === resolved)) {
            if (aboutEditStatus) {
                aboutEditStatus.textContent = `${resolved} is already in the list.`;
                aboutEditStatus.className   = 'about-edit-status error';
            }
            return;
        }

        stagedLangs.push({ language: resolved, level: levelIdx });
        _aboutDirty = true; // B-09
        renderStagedLangs();

        if (aboutLangSearch)   aboutLangSearch.value = '';
        if (aboutLangDropdown) aboutLangDropdown.classList.remove('open');
        if (aboutEditStatus)   { aboutEditStatus.textContent = ''; aboutEditStatus.className = 'about-edit-status'; }
    });
}

// ── ABOUT EDIT — SAVE ─────────────────────────────────────────

function setAboutEditStatus(msg, type) {
    if (!aboutEditStatus) return;
    aboutEditStatus.textContent = msg;
    aboutEditStatus.className   = 'about-edit-status' + (type ? ` ${type}` : '');
}

if (aboutEditSave) {
    aboutEditSave.addEventListener('click', handleAboutSave);
}

async function handleAboutSave() {
    const bioText = aboutBioInput?.value.trim() || '';

    if (!bioText) { setAboutEditStatus('Bio cannot be empty.', 'error'); if (aboutBioInput) aboutBioInput.focus(); return; }

    aboutEditSave.disabled = true;
    aboutEditSave.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Saving...';
    setAboutEditStatus('', '');

    try {
        const cleanEdu = stagedEdu
            .map(e => ({
                course:      e.course?.trim()      || '',
                school:      e.school?.trim()      || '',
                schoolStart: e.schoolStart         || '',
                schoolEnd:   e.schoolEnd           || '',
                year:        e.year?.trim()        || '',
            }))
            .filter(e => e.course);

        const aboutDoc = {
            bio:        { text: bioText },
            education:  cleanEdu,
            proficiency: stagedLangs,
        };

        // B-06: updateDoc instead of setDoc — won't silently create the doc if missing
        await updateDoc(doc(_dDb, "portfolio", "about"), aboutDoc);
        try {
            const tsSnap  = await getDoc(doc(_dDb, "portfolio", "timestamp"));
            let tsData    = tsSnap.exists() ? (tsSnap.data().data || []) : [];

            // Strip all old education entries
            tsData = tsData.filter(e => e.type !== 'education');

            // Re-add one timeline entry per education
            cleanEdu.forEach(edu => {
                if (!edu.course || !edu.schoolStart) return;
                const [smm, , syyyy] = edu.schoolStart.split('-');
                const timelineDate = (syyyy && smm) ? `${syyyy}-${smm}` : edu.schoolStart;
                tsData.push({
                    type:  'education',
                    title: edu.course,
                    date:  timelineDate,
                    desc:  edu.school || '',
                });
            });

            // B-06: Education sync is a full array rebuild — updateDoc instead of setDoc
            await updateDoc(doc(_dDb, "portfolio", "timestamp"), { data: tsData });
            FETCHED_TIMELINE   = tsData.filter(e => !e.repo && e.type !== 'milestone');
            FETCHED_MILESTONES = tsData.filter(e => e.type === 'milestone');
        } catch (tsErr) {
            console.warn('Timeline upsert failed (non-fatal):', tsErr);
        }

        FETCHED_ABOUT = aboutDoc;

        renderAbout();
        renderTimeline();

        setAboutEditStatus('Saved successfully!', 'success');
        _aboutDirty = false; // B-09: committed to Firestore — no longer dirty
        setTimeout(() => closeAboutEditModal(), 1200);

    } catch (err) {
        console.error('About save error:', err);
        setAboutEditStatus(`Save failed: ${err.message || 'Unknown error'}`, 'error');
        aboutEditSave.disabled = false;
        aboutEditSave.innerHTML = '<i class="fa-solid fa-floppy-disk"></i> SAVE';
    }
}

// handleLangDelete removed — language removal is handled through the About edit modal staged langs UI (stagedLangs.splice + save)

// ── EDU CARD DELETE ───────────────────────────────────────────

function openEduDeleteModal() {
    if (aboutEduDeleteConfirm) {
        aboutEduDeleteConfirm.disabled = false;
        aboutEduDeleteConfirm.innerHTML = '<i class="fa-solid fa-trash"></i> YES, DELETE';
    }
    if (aboutEduDeleteOverlay) aboutEduDeleteOverlay.classList.add('open');
}

function closeEduDeleteModal() {
    if (aboutEduDeleteOverlay) aboutEduDeleteOverlay.classList.remove('open');
}

if (aboutEduDeleteClose)  aboutEduDeleteClose.addEventListener('click', closeEduDeleteModal);
if (aboutEduDeleteCancel) aboutEduDeleteCancel.addEventListener('click', closeEduDeleteModal);
if (aboutEduDeleteOverlay) {
    aboutEduDeleteOverlay.addEventListener('click', (e) => {
        if (e.target === aboutEduDeleteOverlay) closeEduDeleteModal();
    });
}

if (aboutEduDeleteConfirm) {
    aboutEduDeleteConfirm.addEventListener('click', async () => {
        aboutEduDeleteConfirm.disabled = true;
        aboutEduDeleteConfirm.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Deleting...';

        try {
            const eduArr = Array.isArray(FETCHED_ABOUT.education)
                ? [...FETCHED_ABOUT.education]
                : (FETCHED_ABOUT.education?.course ? [FETCHED_ABOUT.education] : []);

            if (eduDeleteTargetIdx >= 0 && eduDeleteTargetIdx < eduArr.length) {
                eduArr.splice(eduDeleteTargetIdx, 1);
            }

            const aboutDoc = { ...FETCHED_ABOUT, education: eduArr };
            // B-06: updateDoc instead of setDoc
            await updateDoc(doc(_dDb, "portfolio", "about"), aboutDoc);
            FETCHED_ABOUT.education = eduArr;

            // Rebuild timeline education entries
            try {
                const tsSnap = await getDoc(doc(_dDb, "portfolio", "timestamp"));
                if (tsSnap.exists()) {
                    let tsData = (tsSnap.data().data || []).filter(e => e.type !== 'education');
                    eduArr.forEach(edu => {
                        if (!edu.course || !edu.schoolStart) return;
                        const [smm, , syyyy] = edu.schoolStart.split('-');
                        const timelineDate = (syyyy && smm) ? `${syyyy}-${smm}` : edu.schoolStart;
                        tsData.push({ type: 'education', title: edu.course, date: timelineDate, desc: edu.school || '' });
                    });
                    // B-06: Education sync is a full array rebuild — updateDoc instead of setDoc
                    await updateDoc(doc(_dDb, "portfolio", "timestamp"), { data: tsData });
                    FETCHED_TIMELINE   = tsData.filter(e => !e.repo && e.type !== 'milestone');
                    FETCHED_MILESTONES = tsData.filter(e => e.type === 'milestone');
                }
            } catch (tsErr) {
                console.warn('Timeline edu remove failed (non-fatal):', tsErr);
            }

            eduDeleteTargetIdx = -1;
            closeEduDeleteModal();
            renderAbout();
            renderTimeline();
        } catch (err) {
            console.error('Edu delete error:', err);
            aboutEduDeleteConfirm.disabled = false;
            aboutEduDeleteConfirm.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> FAILED';
            setTimeout(() => { aboutEduDeleteConfirm.innerHTML = '<i class="fa-solid fa-trash"></i> YES, DELETE'; }, 2000);
        }
    });
}

// ── GITHUB API HELPERS ────────────────────────────────────────

async function ghGetSHA(path) {
    const res = await fetch(
        `https://api.github.com/repos/${GH_OWNER}/${GH_REPO}/contents/${path}`,
        { headers: { Authorization: `Bearer ${GH_TOKEN}` } }
    );
    if (!res.ok) return null;
    const json = await res.json();
    return json.sha || null;
}

async function ghPushFile(path, base64Content, commitMessage, sha = null) {
    const body = { message: commitMessage, content: base64Content };
    if (sha) body.sha = sha;
    const res = await fetch(
        `https://api.github.com/repos/${GH_OWNER}/${GH_REPO}/contents/${path}`,
        {
            method:  'PUT',
            headers: {
                Authorization:  `Bearer ${GH_TOKEN}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(body),
        }
    );
    if (!res.ok) throw new Error(`GitHub push failed: ${res.status}`);
    return await res.json();
}

async function ghDeleteFile(path, commitMessage) {
    const sha = await ghGetSHA(path);
    if (!sha) throw new Error(`File not found on GitHub: ${path}`);
    const res = await fetch(
        `https://api.github.com/repos/${GH_OWNER}/${GH_REPO}/contents/${path}`,
        {
            method:  'DELETE',
            headers: {
                Authorization:  `Bearer ${GH_TOKEN}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ message: commitMessage, sha }),
        }
    );
    if (!res.ok) throw new Error(`GitHub delete failed: ${res.status}`);
    return await res.json();
}

// ── BOOT ──────────────────────────────────────────────────────

// Q-09: Loading state helpers — adds/removes a CSS class on each section root
// so the UI can show a skeleton or spinner instead of empty content during fetch.
const _bootSections = ['homeDocsGrid', 'timelineRoot', 'projectsRoot', 'certsRoot'];
function _setLoadingState(on) {
    _bootSections.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.classList.toggle('loading', on);
    });
}

async function boot() {
    _setLoadingState(true);
    try { await loadAllData(); }  catch(e) { console.warn('loadAllData failed:', e); }
    _setLoadingState(false);
    try { renderTimeline(); }     catch(e) { console.warn('renderTimeline failed:', e); }
    try { renderProjects(); }     catch(e) { console.warn('renderProjects failed:', e); }
    try { await renderDocs(); }   catch(e) { console.warn('renderDocs failed:', e); }
    try { renderAbout(); }        catch(e) { console.warn('renderAbout failed:', e); }
    try { renderCerts(); }        catch(e) { console.warn('renderCerts failed:', e); }
    try { populateStats(); }      catch(e) { console.warn('populateStats failed:', e); }
}

// ── AUTH-GATED STARTUP ────────────────────────────────────────

(async () => {
    // Always check for a valid session — URL param is just the login trigger
    const verified = await verifyEditorAccess();
    if (verified) {
        isEditor = true;

        // GitHub credentials — extracted from cache ONLY after editor is confirmed.
        // Visitors never reach this block, so GH_TOKEN never enters their JS scope.
        const gh = _credentialsCache?.github || {};
        GH_TOKEN = gh.token || null;
        GH_OWNER = gh.owner || null;
        GH_REPO  = gh.repo  || null;

        // Clear the cache — the raw credentials object should not linger in memory.
        _credentialsCache = null;

        // Clean up the URL param if present — session is the real gate
        if (_editRequested) {
            window.history.replaceState({}, "", window.location.pathname);
        }
    } else if (_editRequested) {
        // Had the param but no valid session — strip it and clear cache
        window.history.replaceState({}, "", window.location.pathname);
        _credentialsCache = null;
    } else {
        // Visitor session — clear cache so raw credentials don't linger
        _credentialsCache = null;
    }
    initBadge();
    boot();
    if (isEditor && menuEdit) menuEdit.classList.add('visible');
})();

// ── BADGE DROPDOWN ────────────────────────────────────────────

// Q-10: Global Escape key handler — closes whichever overlay is currently open.
// Checked in priority order: deepest/most-modal first.
document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    if (aboutEduDeleteOverlay?.classList.contains('open'))  { closeEduDeleteModal();        return; }
    if (certDeleteOverlay?.classList.contains('open'))      { closeCertDeleteModal();        return; }
    if (docDeleteOverlay?.classList.contains('open'))       { closeDocDeleteModal();         return; }
    if (projectDeleteOverlay?.classList.contains('open'))   { closeProjectDeleteModal();     return; }
    if (milestoneDeleteOverlay?.classList.contains('open')) { closeMilestoneDeleteModal();   return; }
    if (certUploadOverlay?.classList.contains('open'))      { closeCertUploadModal();        return; }
    if (docUploadOverlay?.classList.contains('open'))       { closeDocUploadModal();         return; }
    if (projectAddOverlay?.classList.contains('open'))      { closeProjectAddModal();        return; }
    if (milestoneAddOverlay?.classList.contains('open'))    { closeMilestoneAddModal();      return; }
    if (levelsOverlay?.classList.contains('open'))          { levelsOverlay.classList.remove('open'); return; }
    if (certOverlay?.classList.contains('open'))            { certOverlay.classList.remove('open');   return; }
    if (aboutEditOverlay?.classList.contains('open'))       { closeAboutEditModal();         return; }
    if (faqOverlay?.classList.contains('open'))             { faqOverlay.classList.remove('open');    return; }
});

const badgeWrap     = document.getElementById('badgeWrap');
const badgeDropdown = document.getElementById('badgeDropdown');
const menuFaq       = document.getElementById('menuFaq');
const menuEdit      = document.getElementById('menuEdit');
const menuLeave     = document.getElementById('menuLeave');
const faqOverlay    = document.getElementById('faqOverlay');
const faqClose      = document.getElementById('faqClose');

// menuEdit visibility handled in auth-gated startup

if (badgeWrap) {
    badgeWrap.querySelector('.mode-badge').addEventListener('click', (e) => {
        e.stopPropagation();
        badgeWrap.classList.toggle('open');
    });
}

document.addEventListener('click', (e) => {
    if (badgeWrap && !badgeWrap.contains(e.target)) {
        badgeWrap.classList.remove('open');
    }
    if (!e.target.closest('.doc-card')) {
        document.querySelectorAll('.doc-card.expanded').forEach(c => c.classList.remove('expanded'));
    }
    if (!e.target.closest('.timeline-entry')) {
        document.querySelectorAll('.timeline-entry.expanded').forEach(c => c.classList.remove('expanded'));
    }
    if (!e.target.closest('.project-card')) {
        document.querySelectorAll('.project-card.expanded').forEach(c => c.classList.remove('expanded'));
    }
});

if (menuFaq) {
    menuFaq.addEventListener('click', () => {
        badgeWrap.classList.remove('open');
        faqOverlay.classList.add('open');
    });
}

if (faqClose) {
    faqClose.addEventListener('click', () => faqOverlay.classList.remove('open'));
}

if (faqOverlay) {
    faqOverlay.addEventListener('click', (e) => {
        if (e.target === faqOverlay) faqOverlay.classList.remove('open');
    });
}

// B-09: warn before unload while in edit mode (browser back, tab close, etc.)
function _onBeforeUnload(e) {
    e.preventDefault();
    e.returnValue = '';
}

if (menuEdit) {
    menuEdit.addEventListener('click', () => {
        badgeWrap.classList.remove('open');

        if (isEditMode) {
            // B-09: guard exit — warn if about modal has unsaved changes
            if (_aboutDirty && aboutEditOverlay?.classList.contains('open')) {
                const go = confirm(
                    'You have unsaved changes in the About editor.\n' +
                    'Exit edit mode anyway? Your changes will be lost.'
                );
                if (!go) return;
            }
            window.removeEventListener('beforeunload', _onBeforeUnload);
        } else {
            // Entering edit mode — register unload guard
            window.addEventListener('beforeunload', _onBeforeUnload);
        }

        setEditMode(!isEditMode);
        menuEdit.innerHTML = isEditMode
            ? '<i class="fa-solid fa-pen-to-square"></i> EXIT EDIT'
            : '<i class="fa-solid fa-pen-to-square"></i> EDIT';

        // Reload when exiting edit mode
        if (!isEditMode) {
            setTimeout(() => location.reload(), 2000);
        }
    });
}

if (menuLeave) {
    menuLeave.addEventListener('click', async () => {
        await signOut(_dAuth);
        window.location.href = '../index.html';
    });
}
