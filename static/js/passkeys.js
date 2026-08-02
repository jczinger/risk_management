/* ==========================================================================
   Passkey (WebAuthn) ceremonies, browser side.

   The server hands over ready-made options as JSON; this file's only real job is the
   base64url ↔ ArrayBuffer conversion the WebAuthn API requires, plus turning the
   browser's error messages into something an admin can act on.

   No dependencies, no build step. Loaded on the sign-in page and on account security.
   ========================================================================== */

(function () {
  "use strict";

  /* --- base64url helpers ------------------------------------------------- */

  function b64urlToBuffer(value) {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/");
    const raw = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i += 1) bytes[i] = raw.charCodeAt(i);
    return bytes.buffer;
  }

  function bufferToB64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i += 1) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function csrfToken() {
    const match = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]*)/);
    if (match) return decodeURIComponent(match[1]);
    const input = document.querySelector("input[name=csrfmiddlewaretoken]");
    return input ? input.value : "";
  }

  async function postJSON(url, body) {
    const headers = { "X-CSRFToken": csrfToken(), "X-Requested-With": "fetch" };
    if (body !== undefined) headers["Content-Type"] = "application/json";

    const response = await fetch(url, {
      method: "POST",
      headers: headers,
      credentials: "same-origin",
      body: body === undefined ? null : body,
    });

    let payload = null;
    try {
      payload = await response.json();
    } catch (err) {
      payload = null;
    }

    if (!response.ok) {
      const message = (payload && payload.error) || "The server rejected that request.";
      throw new Error(message);
    }
    return payload;
  }

  /* --- Option/response marshalling -------------------------------------- */

  function decodeCreationOptions(options) {
    options.challenge = b64urlToBuffer(options.challenge);
    options.user.id = b64urlToBuffer(options.user.id);
    if (options.excludeCredentials) {
      options.excludeCredentials = options.excludeCredentials.map(function (cred) {
        return Object.assign({}, cred, { id: b64urlToBuffer(cred.id) });
      });
    }
    return options;
  }

  function decodeRequestOptions(options) {
    options.challenge = b64urlToBuffer(options.challenge);
    if (options.allowCredentials) {
      options.allowCredentials = options.allowCredentials.map(function (cred) {
        return Object.assign({}, cred, { id: b64urlToBuffer(cred.id) });
      });
    }
    return options;
  }

  function encodeRegistration(credential) {
    return {
      id: credential.id,
      rawId: bufferToB64url(credential.rawId),
      type: credential.type,
      // py_webauthn reads transports from here when the authenticator reports them.
      transports: credential.response.getTransports ? credential.response.getTransports() : [],
      clientExtensionResults: credential.getClientExtensionResults(),
      response: {
        clientDataJSON: bufferToB64url(credential.response.clientDataJSON),
        attestationObject: bufferToB64url(credential.response.attestationObject),
        transports: credential.response.getTransports ? credential.response.getTransports() : [],
      },
    };
  }

  function encodeAssertion(credential) {
    return {
      id: credential.id,
      rawId: bufferToB64url(credential.rawId),
      type: credential.type,
      clientExtensionResults: credential.getClientExtensionResults(),
      response: {
        clientDataJSON: bufferToB64url(credential.response.clientDataJSON),
        authenticatorData: bufferToB64url(credential.response.authenticatorData),
        signature: bufferToB64url(credential.response.signature),
        userHandle: credential.response.userHandle
          ? bufferToB64url(credential.response.userHandle)
          : null,
      },
    };
  }

  /* --- Error wording ---------------------------------------------------- */

  function friendlyError(err) {
    if (!err) return "Something went wrong. Please try again.";

    switch (err.name) {
      case "NotAllowedError":
        // Covers both an explicit cancel and a timeout; the API does not distinguish.
        return "That was cancelled or timed out. Try again when you are ready.";
      case "InvalidStateError":
        return "This device already has a passkey registered for this account.";
      case "NotSupportedError":
        return "This browser or device cannot create a passkey. Use the password option instead.";
      case "SecurityError":
        return (
          "The browser refused for security reasons. Passkeys need a secure (https) " +
          "connection on the correct domain."
        );
      case "AbortError":
        return "That request was interrupted. Please try again.";
      case "TypeError":
        // A failed fetch. Safari renders this as the bare words "Type error", Chrome as
        // "Failed to fetch" — neither of which an administrator can act on, and one of
        // which was reported to us as the whole of the error message.
        return "Could not reach the server. Check your connection and try again.";
      default:
        return err.message || "Something went wrong. Please try again.";
    }
  }

  function setStatus(el, message, kind) {
    if (!el) return;
    el.textContent = message || "";
    el.className = message ? "callout callout--" + (kind || "info") : "hidden";
  }

  /* --- Public entry points ---------------------------------------------- */

  async function signIn(config) {
    const status = document.querySelector(config.statusSelector);
    const button = document.querySelector(config.buttonSelector);

    if (!window.PublicKeyCredential) {
      setStatus(status, "This browser does not support passkeys. Use the password option below.", "warning");
      return;
    }

    if (button) button.disabled = true;
    setStatus(status, "Waiting for your passkey…", "info");

    try {
      const options = await postJSON(config.beginUrl);
      const credential = await navigator.credentials.get({
        publicKey: decodeRequestOptions(options),
      });
      if (!credential) throw new Error("No passkey was returned.");

      const result = await postJSON(config.finishUrl, JSON.stringify(encodeAssertion(credential)));
      setStatus(status, "Signed in. Taking you through…", "success");
      window.location.href = (result && result.redirect) || config.fallbackRedirect || "/";
    } catch (err) {
      setStatus(status, friendlyError(err), "danger");
      if (button) button.disabled = false;
    }
  }

  async function register(config) {
    const status = document.querySelector(config.statusSelector);
    const button = document.querySelector(config.buttonSelector);
    const labelInput = config.labelSelector ? document.querySelector(config.labelSelector) : null;

    if (!window.PublicKeyCredential) {
      setStatus(status, "This browser does not support passkeys.", "warning");
      return;
    }

    if (button) button.disabled = true;
    setStatus(status, "Follow your device's prompt to create the passkey…", "info");

    try {
      const options = await postJSON(config.beginUrl);
      const credential = await navigator.credentials.create({
        publicKey: decodeCreationOptions(options),
      });
      if (!credential) throw new Error("No passkey was created.");

      // The label travels in the body, not a header. Header values must be ISO-8859-1
      // bytes, and a phone's keyboard turns a typed apostrophe into a curly one (U+2019)
      // without being asked — so "Grammy's" made fetch throw a bare TypeError before the
      // request ever left the browser. Any name outside latin-1 did the same.
      const result = await postJSON(
        config.finishUrl,
        JSON.stringify({
          credential: encodeRegistration(credential),
          label: labelInput ? labelInput.value : "",
        })
      );
      setStatus(status, "Passkey registered.", "success");
      window.location.href = (result && result.redirect) || config.fallbackRedirect || "/";
    } catch (err) {
      // The wording above is deliberately plain; keep the real error for support.
      if (window.console) console.error("Passkey registration failed", err);
      setStatus(status, friendlyError(err), "danger");
      if (button) button.disabled = false;
    }
  }

  window.VMSPasskeys = { signIn: signIn, register: register };
})();
