import { initializeApp } from "https://www.gstatic.com/firebasejs/11.7.1/firebase-app.js";

const _firebaseConfig = {
    apiKey:            "AIzaSyAZLCVYWX2Nn6GYYYHpwSFkZXj2ZjIJhRE",
    authDomain:        "developer-vien-portfolio.firebaseapp.com",
    projectId:         "developer-vien-portfolio",
    storageBucket:     "developer-vien-portfolio.firebasestorage.app",
    messagingSenderId: "830687475736",
    appId:             "1:830687475736:web:4ad1263787f0d1af112b6d"
};

export const firebaseApp = initializeApp(_firebaseConfig);
