/*
 * 2021 Alexander Schoepe, Bochum, DE, BSD-3 license
 */

"use strict";

customElements.define("crypted-data", class extends HTMLElement {
    connectedCallback() {
        new CryptedData(this);
    }
});

function CryptedData(elm) {
    elm.decrypt = decrypt;
    elm.hideGroup = hideGroup;
    elm.hideForm = hideForm;

    Object.defineProperties(elm, {
        'algorithm': {
            get: () => elm.getAttribute('algorithm')
        },
        'group': {
            get: () => elm.getAttribute('group')
        },
        'salt': {
            get: () => elm.getAttribute('salt')
        }
    });

    const txtDec = new TextDecoder();
    let algorithm;
    let encrypted;
    let salt;
    let shadow = elm.attachShadow({ mode: 'closed' });

    function init() {
        let style = document.createElement('style');
        style.textContent =
            '.crypted-data>.encrypted { display: none; } ' +
            '.crypted-data>.decrypted { display: none; padding-top: 5px; padding-bottom: 5px; } ' +
            '.crypted-data.visible>.decrypted { display: block; } ' +
            '.crypted-data>.show { display: inline-block; } ' +
            '.crypted-data.visible>.show { display: none; } ' +
            '.crypted-data>.hide { display: none; } ' +
            '.crypted-data.visible>.hide { display: inline-block; } ' +
            '.crypted-data .password { display: none; position: absolute; padding: 10px; background-color: #f8f9fadd; border: 1px solid #999999; border-radius: 0.25rem; box-shadow: 2px 4px 8px rgba(0, 0, 0, 0.2); } ' +
            '.crypted-data .password.active { display: flex; align-items: center; } ' +
            '.crypted-data .password > input { margin-left: 5px; } ' +
            '.crypted-data .password > input[type=button] { color: red; } ' +
            '.crypted-data .password > input[type=submit] { color: green; } ';
        shadow.appendChild(style);

        let div = document.createElement('div');
        div.classList.add('crypted-data');
        div.innerHTML =
            '<div class="decrypted" part="decrypted"></div>' +
            '<button class="show">&#x1F510;</button>' +
            '<button class="hide">&#x1F512;</button>' +
            '<form class="password">' +
            '  <span>&#x1F511;</span>' +
            '  <input type="password" autocomplete="off">' +
            '  <input type="button" value="&#x2718;">' +
            '  <input type="submit" value="&#x2714;">' +
            '</form>';
        div.querySelector('.show').onclick = getPassword;
        div.querySelector('.hide').onclick = hideGroupAll;
        div.querySelector('.password').onsubmit = showGroup;
        div.querySelector('input[type="button"]').onclick = hideForm;
        shadow.appendChild(div);

        setTimeout(() => {
            algorithm = elm.algorithm;
            elm.removeAttribute('algorithm');
            encrypted = elm.textContent.replace(/\s*/g, '');
            elm.textContent = '';
            salt = elm.salt;
            elm.removeAttribute('salt');
        });
    }
    init();

    function binaryToUint8Array(data) {
        return new Uint8Array(data.split('').map(function (c) { return c.charCodeAt(0); }));
    }

    function base64urlDecode(b64url) {
        return atob((b64url + '==='.slice((b64url.length + 3) % 4)).replace(/-/g, '+').replace(/_/g, '/'))
    }

    function base64urlEncode(data) {
        return btoa(data).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
    }

    function validateKey(str) {
        return str.slice(0, 32) + '\0'.repeat(32 - str.length);
    }

    function escHandler(evt) {
        if (evt.key === "Escape") {
            hideFormAll();
        }
    }

    function getPassword(evt) {
        hideFormAll();
        let f = shadow.querySelector('.password');
        let p = f.querySelector('input[type="password"]');
        p.value = '';
        f.classList.add('active');
        p.focus();
        f.style.top = (evt.currentTarget.offsetTop + 5) + 'px';
        f.style.left = (evt.currentTarget.offsetLeft + 5) + 'px';
        document.addEventListener('keydown', escHandler);
    }

    async function decrypt(password) {
        const key = base64urlEncode(validateKey(password));
        const aesGcmKey = await window.crypto.subtle.importKey(
            'jwk',
            { kty: 'oct', k: key, alg: 'A256GCM', ext: true },
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );

        let baseDiv = shadow.querySelector('.crypted-data');
        let dataDiv = shadow.querySelector('.decrypted');

        try {
            let decryptedBuffer = await window.crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: binaryToUint8Array(base64urlDecode(salt)) },
                aesGcmKey,
                binaryToUint8Array(base64urlDecode(encrypted))
            );
            let decrypted = txtDec.decode(decryptedBuffer);
            dataDiv.innerHTML = decrypted;
            baseDiv.classList.add('visible');
        } catch (err) {
            baseDiv.classList.remove('visible');
            dataDiv.innerHTML = '';
        }
    }

    function showGroup(e) {
        e.preventDefault();
        let f = shadow.querySelector('.password');
        f.classList.remove('active');
        let passE = f.querySelector('input[type="password"]');
        let password = passE.value;
        passE.value = '';
        document.removeEventListener('keydown', escHandler);

        let group = elm.getAttribute('group');
        let list;
        if (group)
            list = document.querySelectorAll('crypted-data[group="' + group + '"]');
        else
            list = document.querySelectorAll('crypted-data:not([group]), crypted-data[group=""]');
        for (let e of list) {
            e.decrypt(password);
        }
    }

    function hideForm() {
        shadow.querySelector('.password').classList.remove('active');
    }

    function hideFormAll() {
        let list = document.querySelectorAll('crypted-data');
        for (let e of list) {
            e.hideForm();
        }
        document.removeEventListener('keydown', escHandler);
    }

    function hideGroup() {
        shadow.querySelector('.crypted-data').classList.remove('visible');
        shadow.querySelector('.decrypted').innerHTML = '';
    }

    function hideGroupAll() {
        let group = elm.getAttribute('group');
        let list;
        if (group)
            list = document.querySelectorAll('crypted-data[group="' + group + '"]');
        else
            list = document.querySelectorAll('crypted-data:not([group]), crypted-data[group=""]');
        for (let e of list) {
            e.hideGroup();
        }
    }
}

customElements.define("crypted-encoder", class extends HTMLElement {
    connectedCallback() {
        new CryptedEncoder(this);
    }
});

function CryptedEncoder(elm) {
    this.encrypt = encrypt;

    const txtEnc = new TextEncoder();
    let shadow = elm.attachShadow({ mode: 'closed' });

    function init() {
        let style = document.createElement('style');
        style.textContent =
            '.crypted-encoder>div { display: flex; align-items: baseline; margin-bottom: 5px; } ' +
            '.crypted-encoder >div>button { margin-left: 140px; } ' +
            '.crypted-encoder label { width: 140px; }';
        shadow.appendChild(style);

        let div = document.createElement('div');
        div.classList.add('crypted-encoder');
        div.innerHTML =
            '<div>' +
            '  <label for="cePassword">password</label>' +
            '  <input type="password" id="cePassword" size="32">' +
            '</div>' +
            '<div>' +
            '  <label for="ceContent">content to encrypt</label>' +
            '  <textarea id="ceContent" cols="80" rows="4"></textarea>' +
            '</div>' +
            '<div>' +
            '  <button>encrypt</button>' +
            '</div>' +
            '<div>' +
            '  <label for="ceNonce">generated salt</label>' +
            '  <textarea id="ceNonce" cols="20" rows="1" readonly></textarea>' +
            '</div>' +
            '<div>' +
            '  <label for="ceEncrypted">encrypted data</label>' +
            '  <textarea id="ceEncrypted" cols="80" rows="4" readonly></textarea>' +
            '</div>';
        div.querySelector('button').onclick = encrypt;
        shadow.appendChild(div);
    }
    init();

    function byteArrayBase64urlEncode(arr) {
        const b64c = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        const bin = n => n.toString(2).padStart(8, 0);
        const l = arr.length
        let result = '';

        for (let i = 0; i <= (l - 1) / 3; i++) {
            let c1 = i * 3 + 1 >= l;
            let c2 = i * 3 + 2 >= l;
            let chunk = bin(arr[3 * i]) + bin(c1 ? 0 : arr[3 * i + 1]) + bin(c2 ? 0 : arr[3 * i + 2]);
            let r = chunk.match(/.{1,6}/g).map((x, j) => j == 3 && c2 ? '=' : (j == 2 && c1 ? '=' : b64c[+('0b' + x)]));
            result += r.join('');
        }
        return result.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    function base64urlEncode(data) {
        return btoa(data).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
    }

    function validateKey(str) {
        return str.slice(0, 32) + '\0'.repeat(32 - str.length);
    }

    async function encrypt() {
        let password = shadow.getElementById('cePassword').value;
        let key = base64urlEncode(validateKey(password));
        let content = shadow.getElementById('ceContent').value;

        const aesGcmKey = await window.crypto.subtle.importKey(
            'jwk',
            { kty: 'oct', k: key, alg: 'A256GCM', ext: true },
            { name: 'AES-GCM' },
            false,
            ['encrypt']
        );
        const iv = crypto.getRandomValues(new Uint8Array(10));
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            aesGcmKey,
            txtEnc.encode(content)
        );
        let b64uEncrypted = byteArrayBase64urlEncode(new Uint8Array(encrypted));

        shadow.getElementById('ceNonce').textContent = byteArrayBase64urlEncode(iv);
        shadow.getElementById('ceEncrypted').innerHTML = b64uEncrypted.match(/.{1,80}/g).join('&#13;&#10;');
    }
}
