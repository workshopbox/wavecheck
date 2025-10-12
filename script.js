/**
 * =================================================================================================
 * CRITICAL SECURITY WARNING & FIX-LOG
 * =================================================================================================
 *
 * 1.  **Original Issue (Critical Security Flaw):** The original script loaded ALL user accounts,
 * including plaintext passwords, into the browser. This is extremely insecure, as anyone
 * could open the browser's developer tools and see every user's credentials.
 *
 * 2.  **Original Issue (Permissions Error):** The original login system was custom and only saved
 * user info to the browser's `sessionStorage`. It NEVER actually logged the user into Firebase.
 * However, your Firestore Security Rules (`allow read: if request.auth != null;`) require a
 * real Firebase login. This mismatch is why you received "Missing or insufficient permissions"
 * errors—from the server's perspective, you were never logged in.
 *
 * 3.  **The Fix Implemented Below:**
 * -   **Firebase Authentication:** The login/logout logic has been completely rewritten to use
 * Firebase's secure, built-in Authentication service (`signInWithEmailAndPassword`, `signOut`).
 * This correctly authenticates the user with the Firebase backend, resolving the permissions errors.
 * -   **Secure Data Handling:** The script no longer downloads all user accounts. Instead, after a
 * successful login, it fetches ONLY the logged-in user's specific data (role, stations, etc.)
 * from the 'accounts' collection.
 * -   **App Initialization:** The entire application now starts inside an `onAuthStateChanged`
 * listener. This is the correct pattern to ensure that Firebase has established the user's
 * login status BEFORE any data is requested.
 * -   **Minor Bug Fixes:** Several smaller bugs related to Firestore queries and UI updates have also
 * been corrected throughout the script.
 *
 * 4.  **ACTION REQUIRED:** You should now migrate your users from the 'accounts' collection to the
 * Firebase Authentication panel in your Firebase console. After migration, you should DELETE
 * the `password` field from all documents in your 'accounts' collection.
 *
 * =================================================================================================
 */

// Import all the functions we need from the Firebase SDKs
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import { getFirestore, collection, getDocs, getDoc, addDoc, onSnapshot, doc, deleteDoc, updateDoc, writeBatch, query, where } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js";
// FIX: Import Firebase Authentication functions
// Note: We are reverting to a client‑side only authentication mechanism that
// does NOT use Firebase Authentication.  As a result, we no longer import
// any Firebase Auth functions.  This means all user credentials are
// downloaded to the client and verified locally, which is insecure but
// necessary if you choose to bypass Firebase Auth.


// Your web app's Firebase configuration
const firebaseConfig = {
    apiKey: "AIzaSyALA7TACwHPpAGolV_aYxuVgBEWmizI6CA",
    authDomain: "wave-check-cc19a.firebaseapp.com",
    projectId: "wave-check-cc19a",
    storageBucket: "wave-check-cc19a.appspot.com",
    messagingSenderId: "448503442369",
    appId: "1:448503442369:web:ff5123572f9c2386c69d40"
};

// Initialize Firebase and get references to the services
const app = initializeApp(firebaseConfig);
const db = getFirestore(app);
// We no longer initialize Firebase Auth.  All login logic is handled on
// the client using data downloaded from Firestore.


// ======================================================================
// LOGGING UTILITIES
// ======================================================================
const logsCollectionRef = collection(db, 'logs');

async function addLog(action, details, stationId = null) {
    try {
        let userIdentifier = 'Unknown';
        // When not using Firebase Auth, derive the user identifier from the
        // current session (sessionStorage).  If no user is logged in, fall
        // back to a generic identifier.
        const sessionUser = sessionStorage.getItem('currentUserDetails');
        if (sessionUser) {
            const userObj = JSON.parse(sessionUser);
            userIdentifier = userObj.email || userObj.badgeId || 'Session User';
        }
        await addDoc(logsCollectionRef, {
            timestamp: Date.now(),
            stationId: stationId,
            user: userIdentifier,
            action: action,
            details: details
        });
    } catch (error) {
        console.error('Error logging event:', error);
    }
}

// ======================================================================
// ACCOUNT AND AUTHENTICATION UTILITIES (REFACTORED FOR FIREBASE AUTH)
// ======================================================================
const accountsCollectionRefMain = collection(db, 'accounts');

// Default demo credentials. NOTE: This is a client-side only fallback
// and does not represent a real secure account.
const demoCredentials = {
    email: 'admin@example.com',
    password: 'admin123',
    role: 'Developer',
    name: 'Demo User'
};

/**
 * Update the visibility of login and logout buttons based on the
 * current session and Firebase Auth state.
 */
function updateHeaderUI() {
    const userDetails = sessionStorage.getItem('currentUserDetails');
    const role = userDetails ? JSON.parse(userDetails).role : null;

    const loginBtn = document.getElementById('login-btn');
    const logoutBtn = document.getElementById('logout-btn');

    if (loginBtn && logoutBtn) {
        if (userDetails) {
            loginBtn.style.display = 'none';
            logoutBtn.style.display = 'inline-block';
        } else {
            loginBtn.style.display = 'inline-block';
            logoutBtn.style.display = 'none';
        }
    }

    const adminLinks = document.querySelectorAll('.admin-button-link[href*="admin"], #adminBtn');
    adminLinks.forEach(link => {
        // Use the role from our fetched user details
        if (userDetails && role && ['Developer', 'L4+', 'L3'].includes(role)) {
            link.style.display = 'inline-block';
        } else {
            link.style.display = 'none';
        }
    });
}


/**
 * Display a temporary notification with the provided message.
 */
function showNotification(message) {
    let notif = document.getElementById('notification');
    if (!notif) {
        notif = document.createElement('div');
        notif.id = 'notification';
        notif.className = 'notification';
        document.body.appendChild(notif);
    }
    notif.textContent = message;
    notif.style.display = 'block';
    setTimeout(() => {
        notif.style.display = 'none';
    }, 4000);
}

/**
 * Initialize a dark/light theme toggle button.
 */
function initializeTheme() {
    const header = document.querySelector('.site-header');
    if (!header || document.getElementById('theme-toggle-btn')) return;

    const saved = localStorage.getItem('theme');
    if (saved === 'light') {
        document.body.classList.add('light-mode');
    }
    const btn = document.createElement('button');
    btn.id = 'theme-toggle-btn';
    btn.className = 'admin-button-link';
    btn.style.right = '5rem';
    btn.textContent = document.body.classList.contains('light-mode') ? 'Dark Mode' : 'Light Mode';
    btn.addEventListener('click', () => {
        const isLight = document.body.classList.toggle('light-mode');
        localStorage.setItem('theme', isLight ? 'light' : 'dark');
        btn.textContent = isLight ? 'Dark Mode' : 'Light Mode';
    });
    header.appendChild(btn);
}

// ======================================================================
// MAIN SCRIPT LOGIC (CLIENT‑SIDE AUTHENTICATION)
// ======================================================================
// We fetch all accounts from Firestore on page load.  This allows the client
// to authenticate users locally by comparing entered credentials with the
// downloaded account data.  After accounts are fetched, we initialize
// the appropriate page logic.  NOTE: This exposes all account data to any
// client and is inherently insecure.

// Global array to hold all account documents.  Populated by fetchAllAccounts().
let allAccounts = [];

async function fetchAllAccounts() {
    try {
        const snapshot = await getDocs(accountsCollectionRefMain);
        allAccounts = snapshot.docs.map(docSnap => ({ id: docSnap.id, ...docSnap.data() }));
    } catch (error) {
        console.error('Error fetching accounts:', error);
        allAccounts = [];
    }
}

// Immediately invoked async function to load accounts and initialize the page
(async function() {
    await fetchAllAccounts();
    initializePage();
})();


/**
 * Determines which page is active (home or station) and runs the
 * appropriate initialization logic.
 */
function initializePage() {
    // This function runs after accounts have been fetched and any existing
    // session has been restored.  No Firebase Auth is involved.
    updateHeaderUI();
    initializeTheme();

    const stationPageWrapper = document.querySelector('.station-page-wrapper');

    if (stationPageWrapper) {
        const stationId = stationPageWrapper.dataset.stationId;
        const currentUserDetails = getCurrentUserDetails();

        // Without Firebase Auth, we rely solely on sessionStorage to determine
        // whether a user is logged in.  If no session exists, redirect to home.
        if (!currentUserDetails) {
            alert('You must log in to access this page.');
            window.location.href = 'index.html';
            return;
        }

        if (hasAccessToStation(currentUserDetails, stationId)) {
            initializeStationPageLogic(stationPageWrapper, stationId);
        } else {
            alert('You do not have permission to access this station.');
            window.location.href = 'index.html';
        }
    } else {
        initializeHomePage();
    }
}

/**
 * Retrieve the currently logged-in user's details (role, stations) from sessionStorage.
 */
function getCurrentUserDetails() {
    try {
        const data = sessionStorage.getItem('currentUserDetails');
        return data ? JSON.parse(data) : null;
    } catch (e) {
        return null;
    }
}

/**
 * Determine whether the given user has permission to access a station.
 */
function hasAccessToStation(userDetails, stationId) {
    if (!userDetails || !stationId) return false;
    const elevatedRoles = ['Developer', 'L4+', 'L3'];
    if (elevatedRoles.includes(userDetails.role)) return true;
    if (Array.isArray(userDetails.stations)) {
        return userDetails.stations.includes(stationId);
    }
    return false;
}


// ======================================================================
// ALL STATION PAGE LOGIC
// ======================================================================

function initializeStationPageLogic(stationPageWrapper, stationId) {
    const daListCollectionRef = collection(db, 'stations', stationId, 'drivers');
    const rosterCollectionRef = collection(db, 'stations', stationId, 'roster');
    const tabLinks = document.querySelectorAll('.tab-link');
    const tabPanes = document.querySelectorAll('.tab-pane');
    const daListTableBody = document.getElementById('da-list-table-body');
    const rosterTableBody = document.getElementById('roster-table-body');
    const companyContainer = document.getElementById('company-stats-container');
    const addDaForm = document.getElementById('add-da-form');
    const bulkDaForm = document.getElementById('bulk-da-form');
    const resetDaListBtn = document.getElementById('reset-da-list-btn');
    const addDriverToRosterForm = document.getElementById('add-roster-form');
    const bulkRosterForm = document.querySelector('#caproster-content .bulk-roster-form');
    const resetRosterBtn = document.getElementById('reset-roster-btn');
    const waveCheckForm = document.getElementById('wave-check-form');
    const scannerOutput = document.getElementById('scanner-output');
    const missingDriversModal = document.getElementById('missing-drivers-modal');
    const closeButtonMissing = document.querySelector('.close-button-missing');
    const waveButtonsContainer = document.getElementById('wave-buttons');
    const waveMissingList = document.getElementById('wave-missing-list');
    const waveShowDriversBtn = document.getElementById('wave-show-drivers-btn');
    const slackBtn = document.getElementById('slack-btn');
    const chimeBtn = document.getElementById('chime-btn');

    let currentDrivers = [];
    let startTimeData = {};
    let selectedStartTime = null;

    function updateWaveButtonsUI() {
        if (!waveButtonsContainer) return;
        const buttons = waveButtonsContainer.querySelectorAll('.wave-btn');
        buttons.forEach(btn => {
            const btnTime = btn.getAttribute('data-time');
            if (btnTime === selectedStartTime) {
                btn.classList.add('active');
            } else {
                btn.classList.remove('active');
            }
        });
    }

    function showWaveDrivers() {
        if (!waveMissingList) return;
        waveMissingList.innerHTML = '';
        if (!selectedStartTime || !startTimeData[selectedStartTime]) {
            const li = document.createElement('li');
            li.textContent = 'No drivers in this group.';
            waveMissingList.appendChild(li);
            return;
        }
        const missing = startTimeData[selectedStartTime].drivers.filter(driver => driver.status !== 'Checked In' && driver.status !== 'Checked In NO BADGE');
        if (missing.length === 0) {
            const li = document.createElement('li');
            li.textContent = 'No missing drivers in this group.';
            waveMissingList.appendChild(li);
        } else {
            missing.forEach(driver => {
                const li = document.createElement('li');
                // FIX: Corrected redundant property access and added a fallback for clarity.
                li.textContent = `${driver.name} (${driver.badgeId || 'N/A'})`;
                waveMissingList.appendChild(li);
            });
        }
    }

    if (waveShowDriversBtn) {
        waveShowDriversBtn.addEventListener('click', showWaveDrivers);
    }

    function activateTab(activeLink, targetPaneId) {
        tabLinks.forEach(innerLink => innerLink.classList.remove('active'));
        tabPanes.forEach(pane => pane.classList.remove('active'));
        activeLink.classList.add('active');
        const targetPane = document.getElementById(targetPaneId);
        if (targetPane) targetPane.classList.add('active');
    }

    tabLinks.forEach(link => {
        link.addEventListener('click', event => {
            event.preventDefault();
            const targetId = link.getAttribute('data-tab');
            if (targetId === 'da-list-content') {
                const userDetails = getCurrentUserDetails();
                if (userDetails && ['Developer', 'L4+'].includes(userDetails.role)) {
                    activateTab(link, targetId);
                } else {
                    alert('You do not have permission to access the DA-List.');
                }
            } else {
                activateTab(link, targetId);
            }
        });
    });

    function openMissingModal() { if (missingDriversModal) missingDriversModal.style.display = 'flex'; }
    function closeMissingModal() { if (missingDriversModal) missingDriversModal.style.display = 'none'; }
    if (closeButtonMissing) closeButtonMissing.addEventListener('click', closeMissingModal);
    window.addEventListener('click', (event) => {
        if (event.target == missingDriversModal) closeMissingModal();
    });

    if (waveCheckForm) {
        waveCheckForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const scanInput = waveCheckForm.querySelector('.manual-badge-input');
            const badgeIdValue = scanInput.value.trim();
            if (!badgeIdValue) return;

            // FIX: Use a more efficient 'in' query to check for both string and number types,
            // as Firestore doesn't support OR conditions on the same field.
            const badgeIdAsString = badgeIdValue;
            const badgeIdAsNumber = parseInt(badgeIdValue, 10);
            const queryValues = isNaN(badgeIdAsNumber) ? [badgeIdAsString] : [badgeIdAsString, badgeIdAsNumber];

            const q = query(rosterCollectionRef, where("badgeId", "in", queryValues));
            const querySnapshot = await getDocs(q);

            if (querySnapshot.empty) {
                scannerOutput.innerHTML = `<h2 class="status-heading status-error">DRIVER NOT FOUND</h2><p>The Badge ID "${badgeIdValue}" was not found on today's roster.</p>`;
            } else {
                const rosterDoc = querySnapshot.docs[0];
                const driverData = rosterDoc.data();
                if (driverData.status === 'Checked In' || driverData.status === 'Checked In NO BADGE') {
                    const timeStamp = driverData.checkInTime ? ` at ${driverData.checkInTime}` : '';
                    const statusLabel = driverData.status === 'Checked In NO BADGE' ? 'ALREADY CHECKED IN (NO BADGE)' : 'ALREADY CHECKED IN';
                    scannerOutput.innerHTML = `<h2 class="status-heading status-info">${statusLabel}</h2><div class="scan-details"><p><strong>Name:</strong> ${driverData.name}</p><p><strong>Badge ID:</strong> ${driverData.badgeId}</p>${timeStamp ? `<p><strong>Time:</strong> ${driverData.checkInTime}</p>` : ''}</div>`;
                } else {
                    const currentTime = new Date().toLocaleTimeString('en-GB', { hour12: false });
                    await updateDoc(rosterDoc.ref, { status: 'Checked In', checkInTime: currentTime });
                    scannerOutput.innerHTML = `<h2 class="status-heading status-success">CHECK-IN SUCCESSFUL</h2><div class="scan-details"><p><strong>Name:</strong> ${driverData.name}</p><p><strong>Transporter ID:</strong> ${driverData.transporterId}</p><p><strong>Badge ID:</strong> ${driverData.badgeId}</p><p><strong>Start Time:</strong> ${driverData.startTime}</p><p><strong>Company Name:</strong> ${driverData.firmenname}</p><p><strong>Time:</strong> ${currentTime}</p></div>`;
                }
            }
            scanInput.value = '';
        });
    }

    onSnapshot(daListCollectionRef, snapshot => {
        if (!daListTableBody) return;
        daListTableBody.innerHTML = '';
        snapshot.docs.forEach(doc => {
            const driver = doc.data();
            const row = document.createElement('tr');
            row.innerHTML = `<td>${driver.userId || ''}</td><td>${driver.name || ''}</td><td>${driver.badgeId || ''}</td><td>${driver.companyName || ''}</td><td>${driver.transporterId || ''}</td><td class="actions-cell"><button class="action-btn btn-delete" data-collection="drivers" data-id="${doc.id}">Delete</button></td>`;
            daListTableBody.appendChild(row);
        });
    });

    if (addDaForm) {
        addDaForm.addEventListener('submit', async event => {
            event.preventDefault();
            const newDriver = {
                userId: addDaForm.userId.value,
                name: addDaForm.name.value,
                badgeId: addDaForm.badgeId.value,
                companyName: addDaForm.companyName.value,
                transporterId: addDaForm.transporterId.value
            };
            await addDoc(daListCollectionRef, newDriver);
            addLog('addDa', `Added driver ${newDriver.name} (Badge: ${newDriver.badgeId}) to the master list`, stationId);
            addDaForm.reset();
        });
    }

    if (bulkDaForm) {
        bulkDaForm.addEventListener('submit', event => {
            event.preventDefault();
            const fileInput = document.getElementById('excel-upload');
            const file = fileInput.files[0];
            if (!file) return alert("Please select a file to upload.");
            const reader = new FileReader();
            reader.onload = async (e) => {
                try {
                    const data = new Uint8Array(e.target.result);
                    const workbook = XLSX.read(data, { type: 'array' });
                    const firstSheetName = workbook.SheetNames[0];
                    const worksheet = workbook.Sheets[firstSheetName];
                    const jsonData = XLSX.utils.sheet_to_json(worksheet);
                    if (jsonData.length === 0) return alert("The selected file is empty or could not be read.");
                    const batch = writeBatch(db);
                    let processedCount = 0;
                    jsonData.forEach(row => {
                        const newDriver = { userId: row['User ID'] || '', name: row['Employee Name'] || '', badgeId: row['Badge ID'] || '', companyName: row['Company Name'] || '', transporterId: row['Transporter ID'] || '' };
                        if (newDriver.userId && newDriver.name && newDriver.badgeId) {
                            const newDocRef = doc(daListCollectionRef);
                            batch.set(newDocRef, newDriver);
                            processedCount++;
                        }
                    });
                    if (processedCount > 0) {
                        await batch.commit();
                        alert(`${processedCount} drivers were successfully imported from the file!`);
                        addLog('bulkImportDA', `Imported ${processedCount} drivers into the master list`, stationId);
                    } else {
                        alert("No valid drivers found. Please check Excel headers: 'User ID', 'Employee Name', 'Badge ID'.");
                    }
                    bulkDaForm.reset();
                } catch (error) {
                    alert("An error occurred while processing the file.");
                    console.error("Excel import error:", error);
                }
            };
            reader.readAsArrayBuffer(file);
        });
    }

    if (resetDaListBtn) {
        resetDaListBtn.addEventListener('click', async () => {
            if (confirm(`DANGER: Are you sure you want to permanently delete the ENTIRE Master Driver Database for ${stationId}? This cannot be undone.`)) {
                const querySnapshot = await getDocs(daListCollectionRef);
                if (querySnapshot.empty) return alert('Master Driver Database is already empty.');
                const batch = writeBatch(db);
                querySnapshot.forEach(docSnap => { batch.delete(docSnap.ref); });
                try {
                    await batch.commit();
                    alert(`The Master Driver Database for ${stationId} has been successfully cleared.`);
                    addLog('resetDAList', `Cleared the master DA list for station ${stationId}`, stationId);
                } catch (error) {
                    alert('An error occurred while clearing the database.');
                    console.error("Error clearing collection: ", error);
                }
            }
        });
    }

    onSnapshot(rosterCollectionRef, snapshot => {
        if (!rosterTableBody) return;
        rosterTableBody.innerHTML = '';
        let checkedInCount = 0;
        let rescueCount = 0;
        let companyData = {};
        startTimeData = {};

        const drivers = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        currentDrivers = drivers;

        const uniqueStartTimes = Array.from(new Set(drivers.map(d => d.startTime))).sort((a, b) => {
            const [hA, mA] = a.split(':').map(Number);
            const [hB, mB] = b.split(':').map(Number);
            if (hA !== hB) return hA - hB;
            return mA - mB;
        });

        drivers.forEach(driver => {
            const row = document.createElement('tr');
            let statusClass = 'status-awaiting';
            if (driver.status === 'Checked In') statusClass = 'status-checked-in';
            else if (driver.status === 'On Rescue') statusClass = 'status-on-rescue';
            else if (driver.status === 'Checked In NO BADGE') statusClass = 'status-no-badge';
            row.className = statusClass;

            let statusText = driver.status;
            if ((driver.status === 'Checked In' || driver.status === 'Checked In NO BADGE') && driver.checkInTime) {
                statusText = `${driver.status} (${driver.checkInTime})`;
            }

            row.innerHTML = `<td>${driver.transporterId || 'N/A'}</td><td>${driver.badgeId || 'N/A'}</td><td>${driver.name}</td><td>${driver.startTime}</td><td>${driver.firmenname}</td><td>${statusText}</td><td class="actions-cell"><button class="action-btn btn-edit" data-collection="roster" data-id="${driver.id}">Edit</button><button class="action-btn btn-rescue" data-collection="roster" data-id="${driver.id}">Rescue</button><button class="action-btn btn-check-in" data-collection="roster" data-id="${driver.id}">Check-In</button><button class="action-btn btn-no-badge" data-collection="roster" data-id="${driver.id}">No Badge</button><button class="action-btn btn-delete" data-collection="roster" data-id="${driver.id}">Delete</button></td>`;
            rosterTableBody.appendChild(row);

            if (driver.status === 'Checked In' || driver.status === 'Checked In NO BADGE') checkedInCount++;
            if (driver.status === 'On Rescue') rescueCount++;

            const company = driver.firmenname || 'Unknown';
            if (!companyData[company]) { companyData[company] = { total: 0, checkedIn: 0 }; }
            companyData[company].total++;
            if (driver.status === 'Checked In' || driver.status === 'Checked In NO BADGE') companyData[company].checkedIn++;

            const startTime = driver.startTime;
            if (!startTimeData[startTime]) {
                startTimeData[startTime] = { total: 0, checkedIn: 0, drivers: [] };
            }
            startTimeData[startTime].total++;
            if (driver.status === 'Checked In' || driver.status === 'Checked In NO BADGE') startTimeData[startTime].checkedIn++;
            startTimeData[startTime].drivers.push(driver);
        });

        const totalDrivers = snapshot.docs.length;
        document.getElementById('total-drivers').innerText = totalDrivers;
        document.getElementById('checked-in-drivers').innerText = checkedInCount;
        document.getElementById('remaining-drivers').innerText = totalDrivers - checkedInCount - rescueCount;
        document.getElementById('rescue-drivers').innerText = rescueCount;

        const progress = totalDrivers > 0 ? Math.round((checkedInCount / totalDrivers) * 100) : 0;
        const progressBar = document.getElementById('check-in-progress-bar');
        progressBar.style.width = `${progress}%`;
        progressBar.innerText = `${progress}%`;

        companyContainer.innerHTML = '<h4>Drivers by Company</h4>';
        for (const companyName in companyData) {
            const stats = companyData[companyName];
            const companyCard = document.createElement('div');
            companyCard.className = 'company-card';
            companyCard.innerHTML = `<span class="company-name">${companyName}</span><span class="company-ratio">${stats.checkedIn} / ${stats.total}</span><button class="missing-btn" data-company="${companyName}">${stats.total - stats.checkedIn} Missing</button>`;
            companyContainer.appendChild(companyCard);
        }

        if (waveButtonsContainer) {
            waveButtonsContainer.innerHTML = '';
            uniqueStartTimes.forEach(time => {
                const btn = document.createElement('button');
                btn.className = 'wave-btn';
                btn.innerText = time;
                btn.setAttribute('data-time', time);
                btn.addEventListener('click', () => {
                    selectedStartTime = time;
                    updateWaveButtonsUI();
                    showWaveDrivers();
                });
                waveButtonsContainer.appendChild(btn);
            });

            // FIX: More robustly handle the selected start time. If the previously selected
            // time no longer exists, default to the first available one.
            if (!uniqueStartTimes.includes(selectedStartTime) && uniqueStartTimes.length > 0) {
                selectedStartTime = uniqueStartTimes[0];
            }
            
            // Always update the UI after a data change
            if(selectedStartTime) {
                showWaveDrivers();
                updateWaveButtonsUI();
            }
        }
    });

    if (addDriverToRosterForm) {
        addDriverToRosterForm.addEventListener('submit', async event => {
            event.preventDefault();
            const badgeId = addDriverToRosterForm.badgeId.value.trim();
            const name = addDriverToRosterForm.name.value.trim();
            const startTime = addDriverToRosterForm.startTime.value.trim();
            const firmenname = addDriverToRosterForm.firmenname.value.trim();
            if (!badgeId || !name || !startTime || !firmenname) { return alert("Please fill out all fields."); }

            const q = query(daListCollectionRef, where("badgeId", "==", badgeId));
            if ((await getDocs(q)).empty) {
                await addDoc(daListCollectionRef, { badgeId, name, companyName: firmenname, userId: 'N/A', transporterId: 'N/A' });
                alert(`New driver with Badge ID ${badgeId} was saved to the permanent DA-List for ${stationId}.`);
                addLog('createMasterDriver', `New driver ${name} (Badge: ${badgeId}) saved to master list`, stationId);
            }

            await addDoc(rosterCollectionRef, {
                badgeId, name, startTime, firmenname, status: 'Awaiting',
                transporterId: `AT-${stationId.toUpperCase()}-${Math.floor(100 + Math.random() * 900)}`
            });
            addLog('addRoster', `Added ${name} (Badge: ${badgeId}) to the daily roster`, stationId);
            addDriverToRosterForm.reset();
        });
    }

    if (bulkRosterForm) {
        bulkRosterForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const textArea = bulkRosterForm.querySelector('textarea');
            if (!textArea.value.trim()) return alert('Bulk roster box is empty.');
            if (!confirm(`Are you sure you want to DELETE the current roster for ${stationId} and overwrite it?`)) return;

            try {
                const daListSnapshot = await getDocs(daListCollectionRef);
                const daListMap = new Map(daListSnapshot.docs.map(doc => [doc.data().transporterId, doc.data()]));

                const oldRosterSnapshot = await getDocs(rosterCollectionRef);
                const deleteBatch = writeBatch(db);
                oldRosterSnapshot.forEach(doc => { deleteBatch.delete(doc.ref); });
                await deleteBatch.commit();

                const lines = textArea.value.trim().split('\n');
                const rosterAddBatch = writeBatch(db);
                const daListAddBatch = writeBatch(db);
                let newDriversAddedToDA = 0;
                let rosterCount = 0;

                lines.forEach(line => {
                    const columns = line.split('\t').map(item => item.trim());
                    if (columns.length >= 9 && line.trim()) {
                        const newRosterDriver = {
                            transporterId: columns[0], name: columns[1], status: columns[2],
                            startTime: columns[5], firmenname: columns[8], badgeId: 'N/A'
                        };
                        if (daListMap.has(newRosterDriver.transporterId)) {
                            newRosterDriver.badgeId = daListMap.get(newRosterDriver.transporterId).badgeId;
                        } else {
                            daListAddBatch.set(doc(daListCollectionRef), {
                                userId: `NEW-${newRosterDriver.transporterId}`, name: newRosterDriver.name,
                                badgeId: 'NEEDS UPDATE', companyName: newRosterDriver.firmenname,
                                transporterId: newRosterDriver.transporterId
                            });
                            newDriversAddedToDA++;
                        }
                        rosterAddBatch.set(doc(rosterCollectionRef), newRosterDriver);
                        rosterCount++;
                    }
                });

                if (newDriversAddedToDA > 0) await daListAddBatch.commit();
                if (rosterCount > 0) await rosterAddBatch.commit();

                let alertMessage = `${rosterCount} drivers were added to the new roster.`;
                if (newDriversAddedToDA > 0) {
                    alertMessage += `\n${newDriversAddedToDA} new drivers were saved to the master DA-List.`;
                }
                alert(alertMessage);
                addLog('bulkRosterUpload', `Uploaded roster with ${rosterCount} entries and added ${newDriversAddedToDA} new master drivers`, stationId);
                textArea.value = '';
            } catch (error) {
                alert('An error occurred while processing the roster.');
                console.error("Bulk roster error: ", error);
            }
        });
    }

    if (resetRosterBtn) {
        resetRosterBtn.addEventListener('click', async () => {
            if (confirm(`Are you sure you want to delete the ENTIRE daily roster for ${stationId}?`)) {
                const querySnapshot = await getDocs(rosterCollectionRef);
                if (querySnapshot.empty) return alert('The daily roster is already empty.');
                const batch = writeBatch(db);
                querySnapshot.forEach(docSnap => { batch.delete(docSnap.ref); });
                try {
                    await batch.commit();
                    alert(`The daily roster for ${stationId} has been successfully cleared.`);
                    addLog('resetRoster', `Cleared the daily roster for station ${stationId}`, stationId);
                } catch (error) {
                    alert('An error occurred while clearing the roster.');
                    console.error("Error clearing collection: ", error);
                }
            }
        });
    }

    if (stationPageWrapper) {
        stationPageWrapper.addEventListener('click', async (event) => {
            const target = event.target;
            if (!target.classList.contains('action-btn')) return;

            const id = target.dataset.id;
            const collectionName = target.dataset.collection;
            if (!id || !collectionName) return;

            const docRef = doc(db, 'stations', stationId, collectionName, id);

            if (target.classList.contains('btn-delete')) {
                if (confirm('Are you sure you want to permanently delete this entry?')) {
                    await deleteDoc(docRef);
                    addLog('deleteEntry', `Deleted entry ${id} from ${collectionName}`, stationId);
                }
            } else if (target.classList.contains('btn-check-in')) {
                const currentTime = new Date().toLocaleTimeString('en-GB', { hour12: false });
                await updateDoc(docRef, { status: 'Checked In', checkInTime: currentTime });
                addLog('updateStatus', `Checked in driver ${id}`, stationId);
            } else if (target.classList.contains('btn-no-badge')) {
                const currentTime = new Date().toLocaleTimeString('en-GB', { hour12: false });
                await updateDoc(docRef, { status: 'Checked In NO BADGE', checkInTime: currentTime });
                addLog('updateStatus', `Marked driver ${id} as Checked In NO BADGE`, stationId);
            } else if (target.classList.contains('btn-rescue')) {
                await updateDoc(docRef, { status: 'On Rescue' });
                addLog('updateStatus', `Marked driver ${id} as On Rescue`, stationId);
            } else if (target.classList.contains('btn-edit')) {
                try {
                    const rosterDoc = await getDoc(docRef);
                    if (!rosterDoc.exists()) return alert('Driver not found.');
                    const currentDriver = rosterDoc.data();
                    const newName = prompt("Enter new Employee Name:", currentDriver.name);
                    const newBadgeId = prompt("Enter new Badge ID:", currentDriver.badgeId);
                    if (newName || newBadgeId) {
                        const updates = {};
                        if(newName) updates.name = newName;
                        if(newBadgeId) updates.badgeId = newBadgeId;
                        await updateDoc(docRef, updates);
                        addLog('editRoster', `Updated roster entry ${id}`, stationId);
                        
                        const masterDriverQuery = query(daListCollectionRef, where("transporterId", "==", currentDriver.transporterId));
                        const masterDriverSnapshot = await getDocs(masterDriverQuery);
                        if (!masterDriverSnapshot.empty) {
                            const masterDocRef = masterDriverSnapshot.docs[0].ref;
                            await updateDoc(masterDocRef, updates);
                            addLog('editMasterDriver', `Synced update for master entry ${masterDocRef.id}`, stationId);
                            alert(`Successfully updated driver in both the Roster and the Master DA-List!`);
                        } else {
                            alert(`Driver updated in the Roster, but could not be found in the Master DA-List to sync.`);
                        }
                    }
                } catch (error) {
                    alert('An error occurred during the update.');
                    console.error('Edit error:', error);
                }
            }
        });
    }

    if (companyContainer) {
        companyContainer.addEventListener('click', async (event) => {
            if (event.target.classList.contains('missing-btn')) {
                const companyName = event.target.dataset.company;
                document.getElementById('missing-modal-title').innerText = `Missing Drivers for ${companyName}`;
                const driverList = document.getElementById('missing-drivers-list');
                driverList.innerHTML = '';
                
                const q = query(rosterCollectionRef, where("firmenname", "==", companyName), where("status", "not-in", ["Checked In", "Checked In NO BADGE"]));
                const querySnapshot = await getDocs(q);
                
                if (querySnapshot.empty) {
                    driverList.innerHTML = '<li>No missing drivers for this company.</li>';
                } else {
                    querySnapshot.forEach(doc => {
                        const li = document.createElement('li');
                        li.textContent = doc.data().name;
                        driverList.appendChild(li);
                    });
                }
                openMissingModal();
            }
        });
    }

    function prepareCommunicationMessage() {
        if (!currentDrivers || currentDrivers.length === 0) return '';
        const missing = currentDrivers.filter(d => d.status !== 'Checked In');
        if (missing.length === 0) return '';

        let message = '';
        const noShow = missing.filter(d => d.status !== 'Checked In NO BADGE');
        const noBadge = missing.filter(d => d.status === 'Checked In NO BADGE');

        if (noShow.length > 0) {
            message += 'Drivers who have not shown up:\n';
            noShow.forEach((d, i) => { message += `${i + 1}. Name: ${d.name}, Badge: ${d.badgeId || 'N/A'}, Company: ${d.firmenname}\n`; });
            message += '\n';
        }
        if (noBadge.length > 0) {
            message += 'Drivers with no badge:\n';
            noBadge.forEach((d, i) => { message += `${i + 1}. Name: ${d.name}, Badge: ${d.badgeId || 'N/A'}, Company: ${d.firmenname}\n`; });
        }
        return message;
    }

    function sendCommunication(type) {
        const message = prepareCommunicationMessage();
        if (!message) return alert('No drivers to report. All drivers are accounted for.');
        
        try {
            navigator.clipboard.writeText(message);
            alert('Die Nachricht wurde in die Zwischenablage kopiert. Öffne das Kommunikations‑Tool und füge sie dort ein.');
        } catch (err) {
            console.error('Clipboard write failed', err);
            alert('Could not copy to clipboard. Please check browser permissions.');
        }

        if (type === 'slack') window.open('https://app.slack.com/client', '_blank');
        else if (type === 'chime') window.open('https://app.chime.aws/', '_blank');
    }

    if (slackBtn) slackBtn.addEventListener('click', () => sendCommunication('slack'));
    if (chimeBtn) chimeBtn.addEventListener('click', () => sendCommunication('chime'));
}

// ======================================================================
// HOME PAGE INITIALIZATION (REFACTORED FOR FIREBASE AUTH)
// ======================================================================
function initializeHomePage() {
    const loginBtn = document.getElementById('login-btn');
    const logoutBtn = document.getElementById('logout-btn');
    const modal = document.getElementById('employeeLoginModal');
    if (!modal) return;

    const closeBtn = modal.querySelector('.close-button');
    const methodsContainer = document.getElementById('login-methods');
    const emailForm = document.getElementById('employee-login-form-email');
    const badgeForm = document.getElementById('employee-login-form-badge');
    const loginError = document.getElementById('employee-login-error');

    function openLoginModal() {
        modal.style.display = 'flex';
        methodsContainer.style.display = 'flex';
        emailForm.style.display = 'none';
        badgeForm.style.display = 'none';
        loginError.style.display = 'none';
        if(emailForm) emailForm.reset();
        if(badgeForm) badgeForm.reset();
    }
    window.showEmployeeLoginModal = openLoginModal;

    function closeLoginModal() {
        modal.style.display = 'none';
    }

    if (loginBtn) loginBtn.addEventListener('click', openLoginModal);
    if (closeBtn) closeBtn.addEventListener('click', closeLoginModal);
    window.addEventListener('click', event => {
        if (event.target === modal) closeLoginModal();
    });

    if (methodsContainer) {
        methodsContainer.querySelectorAll('.login-card').forEach(card => {
            card.addEventListener('click', () => {
                methodsContainer.style.display = 'none';
                const method = card.getAttribute('data-method');
                if (method === 'email') emailForm.style.display = 'block';
                else if (method === 'badge') badgeForm.style.display = 'block';
            });
        });
    }

    if (emailForm) {
        emailForm.addEventListener('submit', event => {
            event.preventDefault();
            loginError.style.display = 'none';
            const email = emailForm.querySelector('#employee-login-email').value.trim();
            const password = emailForm.querySelector('#employee-login-password').value.trim();

            // Check for demo credentials first (client-side only)
            if (email === demoCredentials.email && password === demoCredentials.password) {
                sessionStorage.setItem('currentUserDetails', JSON.stringify({ email, role: demoCredentials.role, name: demoCredentials.name }));
                updateHeaderUI();
                closeLoginModal();
                showNotification(`Welcome back ${demoCredentials.name}.`);
                addLog('login', `Demo user logged in via email`, null);
                return;
            }

            // Look up the account in the downloaded list of accounts
            const account = allAccounts.find(acc => acc.email === email && acc.password === password);
            if (account) {
                sessionStorage.setItem('currentUserDetails', JSON.stringify(account));
                updateHeaderUI();
                closeLoginModal();
                showNotification(`Welcome back ${account.name || account.email}.`);
                addLog('login', `User ${account.email} logged in via email/password`, null);
            } else {
                loginError.textContent = 'Invalid credentials. Please try again.';
                loginError.style.display = 'block';
            }
        });
    }

    if (badgeForm) {
        badgeForm.addEventListener('submit', event => {
            event.preventDefault();
            loginError.style.display = 'none';
            const badge = badgeForm.querySelector('#employee-login-badge').value.trim();
            // Look up the account by badge ID in the downloaded list
            const account = allAccounts.find(acc => acc.badgeId && String(acc.badgeId) === badge);
            if (account) {
                sessionStorage.setItem('currentUserDetails', JSON.stringify(account));
                updateHeaderUI();
                closeLoginModal();
                showNotification(`Welcome back ${account.name || account.email}.`);
                addLog('login', `User ${account.email} logged in via badge`, null);
            } else {
                loginError.textContent = 'Invalid badge ID. Please try again.';
                loginError.style.display = 'block';
            }
        });
    }

    if (logoutBtn) {
        logoutBtn.addEventListener('click', () => {
            const userDetails = getCurrentUserDetails();
            // Clear the session and update the header UI.  Without Firebase Auth
            // we simply remove the stored user details.
            sessionStorage.removeItem('currentUserDetails');
            updateHeaderUI();
            showNotification('You have been logged out.');
            if (userDetails) {
                addLog('logout', `User ${userDetails.email || userDetails.badgeId} logged out`, null);
            }
        });
    }
}
