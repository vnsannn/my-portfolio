import { firebaseApp }                                        from "./firebase-config.js";
import { getAuth, signInWithEmailAndPassword,
         signInWithPopup, GoogleAuthProvider, signOut }       from "https://www.gstatic.com/firebasejs/11.7.1/firebase-auth.js";
import { getFirestore, doc, getDoc }                          from "https://www.gstatic.com/firebasejs/11.7.1/firebase-firestore.js";

const _auth = getAuth(firebaseApp);
const _db   = getFirestore(firebaseApp);

// ── POST-AUTH CREDENTIAL LOADER (S-02 fix) ───────────────────────────────────
// Credentials are only fetched AFTER Firebase auth succeeds — the user is
// authenticated at call time, so Firestore rules can enforce request.auth != null
// on portfolio/credentials. Never called for unauthenticated visitors.
async function loadCredentialsForVerification() {
    try {
        const snap = await getDoc(doc(_db, "portfolio", "credentials"));
        if (!snap.exists()) return null;
        return snap.data().data || {};
    } catch {
        return null;
    }
}

const backBtn        = document.getElementById("backToVST");
const vstBtn         = document.getElementById("vst");
const logo           = document.getElementById("logo");
const modeLabel      = document.getElementById("mode-label");
const visitorSection = document.getElementById("visitor-section");
const devSection     = document.getElementById("dev-section");
const togglePassword = document.getElementById("togglePassword");
const passwordInput  = document.getElementById("password");
const emailInput     = document.getElementById("email");
const loginBtn       = document.querySelector('#loginForm button[type="submit"]');
const socialBtn      = document.getElementById("socialBtn");

const EMAIL_VALIDATOR = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

if (vstBtn) {
    vstBtn.addEventListener("click", () => {
        window.location.href = "pages/dashboard.html";
    });
}

let _panel = false;

if (logo && modeLabel && visitorSection && devSection) {
    logo.addEventListener("dblclick", () => {
        _panel = !_panel;
        if (_panel) {
            visitorSection.classList.add("hidden");
            setTimeout(() => {
                devSection.classList.add("visible");
                modeLabel.textContent = "DEVELOPER";
            }, 200);
        } else {
            devSection.classList.remove("visible");
            setTimeout(() => {
                visitorSection.classList.remove("hidden");
                modeLabel.textContent = "VISITOR";
            }, 200);
        }
    });
}

if (backBtn && visitorSection && modeLabel && devSection) {
    backBtn.addEventListener("click", () => {
        _panel = false;
        devSection.classList.remove("visible");
        setTimeout(() => {
            visitorSection.classList.remove("hidden");
            modeLabel.textContent = "VISITOR";
            emailInput.value    = "";
            passwordInput.value = "";
        }, 200);
    });
}

togglePassword.addEventListener("click", function () {
    const type = passwordInput.getAttribute("type") === "password" ? "text" : "password";
    passwordInput.setAttribute("type", type);
    this.textContent = type === "password" ? "SHOW" : "HIDE";
});

let btnResetTimer = null;

function triggerInputError(input) {
    const shakeTarget = input.closest(".p-wrapper") || input;
    input.classList.remove("input-error");
    shakeTarget.classList.remove("shake");
    void shakeTarget.offsetWidth;
    input.classList.add("input-error");
    shakeTarget.classList.add("shake");
    shakeTarget.addEventListener("animationend", () => shakeTarget.classList.remove("shake"), { once: true });
    input.addEventListener("animationend",       () => input.classList.remove("input-error"), { once: true });
}

function triggerBtnError(message) {
    if (btnResetTimer) clearTimeout(btnResetTimer);
    loginBtn.classList.remove("btn-error", "btn-success");
    void loginBtn.offsetWidth;
    loginBtn.classList.add("btn-error");
    loginBtn.textContent = message;
    btnResetTimer = setTimeout(() => {
        loginBtn.classList.remove("btn-error");
        loginBtn.textContent = "LOGIN";
        loginBtn.disabled    = false;
    }, 1000);
}

function triggerBtnSuccess() {
    if (btnResetTimer) clearTimeout(btnResetTimer);
    loginBtn.classList.remove("btn-error");
    loginBtn.classList.add("btn-success");
    loginBtn.textContent = "WELCOME BACK, VIEN!";
    loginBtn.disabled    = true;
    setTimeout(() => { window.location.href = "pages/dashboard.html?ref=edit"; }, 1500);
}

const loginForm = document.getElementById("loginForm");
if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const email    = emailInput.value.trim();
        const password = passwordInput.value;

        if (!email)                       { triggerInputError(emailInput);    triggerBtnError("ENTER YOUR EMAIL"); return; }
        if (!EMAIL_VALIDATOR.test(email)) { triggerInputError(emailInput);    triggerBtnError("INVALID EMAIL");    return; }
        if (!password)                    { triggerInputError(passwordInput); triggerBtnError("ENTER YOUR PASSWORD"); return; }

        loginBtn.disabled    = true;
        loginBtn.textContent = "SIGNING IN...";

        try {
            const result = await signInWithEmailAndPassword(_auth, email, password);

            // User is now authenticated — safe to read credentials (S-02 fix).
            // Firestore rules should enforce request.auth != null on this document.
            const creds = await loadCredentialsForVerification();
            if (!creds) {
                await signOut(_auth);
                triggerBtnError("UNAVAILABLE");
                return;
            }
            const allowed      = creds.auth?.allowed    || null;
            const uidEmail     = creds.auth?.uid_email  || null;
            const uidGoogle    = creds.auth?.uid_google || null;
            const uidOk        = result.user.uid === uidEmail || result.user.uid === uidGoogle;
            if (result.user.email !== allowed || !uidOk) {
                await signOut(_auth);
                triggerBtnError("NOT AUTHORIZED");
                return;
            }
            triggerBtnSuccess();
        } catch (err) {
            const code = err.code || "";
            if      (code.includes("wrong-password") || code.includes("invalid-credential")) { triggerInputError(passwordInput); triggerBtnError("WRONG PASSWORD"); }
            else if (code.includes("user-not-found"))   { triggerInputError(emailInput); triggerBtnError("NOT AUTHORIZED"); }
            else if (code.includes("too-many-requests")) { triggerBtnError("TOO MANY ATTEMPTS"); }
            else                                         { triggerBtnError("LOGIN FAILED"); }
        }
    });
}

const googleImg = socialBtn?.querySelector('img[alt="Google Logo"]');
if (googleImg) {
    googleImg.style.cursor = "pointer";
    googleImg.addEventListener("click", async () => {
        const provider = new GoogleAuthProvider();
        // login_hint removed — it relied on the pre-loaded allowed email (S-02 fix)
        try {
            const result = await signInWithPopup(_auth, provider);

            // User is now authenticated — safe to read credentials (S-02 fix).
            const creds = await loadCredentialsForVerification();
            if (!creds) {
                await signOut(_auth);
                triggerBtnError("UNAVAILABLE");
                return;
            }
            const uidGoogle = creds.auth?.uid_google || null;
            if (result.user.uid !== uidGoogle) {
                await signOut(_auth);
                triggerBtnError("NOT AUTHORIZED");
                return;
            }
            triggerBtnSuccess();
        } catch (err) {
            if (err.code !== "auth/popup-closed-by-user") triggerBtnError("GOOGLE SIGN-IN FAILED");
        }
    });
}

const microsoftImg = socialBtn?.querySelector('img[alt="Microsoft Logo"]');
if (microsoftImg) {
    microsoftImg.style.cursor = "pointer";
    microsoftImg.addEventListener("click", () => {
        alert("Microsoft Sign-In is unavailable — Microsoft developer program enrollment required.");
    });
}

// No config loading on page load — credentials are only read after Firebase auth
// succeeds (S-02 fix). The login button is immediately available.
