// #/apps/{handle}/{subpath...}: an application extension rendered in a sandboxed iframe of the dashboard.
//
// The iframe is loaded by POSTing the launch token to it and then the application talks to this host with the
// detcord postMessage protocol (exact origin and iframe source checks on both sides): session tokens,
// navigation sync (the hash always reflects the application path, so reload and back work), toasts, modals, title and resize.

import { applicationsSidebar, navigationExtensions } from "./applicationExtensions";
import { applicationIcon } from "./applicationsUtils";

const FRAME_SANDBOX = "allow-scripts allow-same-origin allow-forms allow-popups allow-downloads allow-modals";
const FRAME_NAME = "pb-application-frame";
const MESSAGE_SOURCE = "detcord";

// the single mounted frame page (reused while only the application path changes)
let active = null;

function routeKey(route) {
    return [route.params.handle, route.query.extension?.[0] || "", route.query.recordId?.[0] || ""].join("\n");
}

// returns the application path and query of the route (the id_token is never kept)
function routeAppPath(route) {
    const subpath = route.params.subpath ? "/" + route.params.subpath : "";
    const query = new URLSearchParams(route.query.q?.[0] || "");
    query.delete("id_token");
    const search = query.toString();

    return subpath ? subpath + (search ? "?" + search : "") : "";
}

function appHash(handle, extension, record, path) {
    const url = new URL(path || "/", "http://x");
    const query = new URLSearchParams();
    if (extension) {
        query.set("extension", extension);
    }
    if (record) {
        query.set("recordId", record);
    }
    url.searchParams.delete("id_token");
    if (url.search) {
        query.set("q", url.search.substring(1));
    }

    const subpath = path ? url.pathname : "";

    return `#/apps/${encodeURIComponent(handle)}${subpath}?${query}`;
}

export async function pageApplicationFrame(route) {
    if (active?.key == routeKey(route) && active.page.isConnected) {
        active.syncPath(routeAppPath(route));
        return active.page;
    }

    await app.store.loadApplicationExtensions();

    active = createFramePage(route);

    return active.page;
}

function createFramePage(route) {
    const handle = route.params.handle;
    const recordId = route.query.recordId?.[0] || "";
    const requestedExtension = route.query.extension?.[0] || "";

    const extensions = (app.store.applicationExtensions || []).filter((e) => e.applicationHandle == handle);
    const ext = extensions.find((e) => e.handle == requestedExtension)
        || navigationExtensions().find((e) => e.applicationHandle == handle);

    const data = store({
        title: ext?.label || handle,
        error: ext ? "" : "This application extension is not available.",
        isLoading: !!ext,
        sessionEnded: false,
        height: 0,
    });

    let appOrigin = "";
    let lastPath = routeAppPath(route);
    let frame;

    app.store.title = data.title;

    function post(message) {
        if (frame?.contentWindow && appOrigin) {
            frame.contentWindow.postMessage({ source: MESSAGE_SOURCE, ...message }, appOrigin);
        }
    }

    async function requestSessionToken(id) {
        try {
            const result = await app.pb.send(
                `/api/applications/installations/${encodeURIComponent(ext.installationId)}/session-token`,
                {
                    method: "POST",
                    body: { extension: ext.handle, recordId },
                    requestKey: null,
                },
            );
            post({ type: "response", id, result: { token: result.sessionToken, expiresIn: result.expiresIn } });
        } catch (err) {
            post({ type: "response", id, error: err?.message || "Failed to get a session token." });
        }
    }

    function openModal(payload) {
        closeModal();

        modalElem = t.div(
            {
                className: "modal popup application-frame-modal",
                onafterclose: (el) => {
                    el?.remove();
                    if (modalElem == el) {
                        modalElem = null;
                    }
                    post({ type: "modal.closed", payload: { id: payload?.id } });
                },
            },
            t.header({ className: "modal-header" }, t.h6({ className: "modal-title" }, String(payload?.title || ""))),
            t.div({ className: "modal-content" }, String(payload?.message || "")),
            t.footer(
                { className: "modal-footer" },
                t.button(
                    { type: "button", className: "btn transparent", onclick: () => app.modals.close(modalElem) },
                    t.span({ className: "txt" }, "Close"),
                ),
            ),
        );

        document.body.appendChild(modalElem);
        app.modals.open(modalElem);
    }

    let modalElem = null;
    function closeModal() {
        if (modalElem) {
            app.modals.close(modalElem, true);
        }
    }

    function onMessage(e) {
        // only the mounted iframe with its exact application origin
        if (!frame || e.source !== frame.contentWindow || e.origin !== appOrigin || e.data?.source !== MESSAGE_SOURCE) {
            return;
        }

        const { type, id, payload } = e.data;

        switch (type) {
            case "hello":
                post({
                    type: "init",
                    payload: {
                        handle,
                        extension: ext.handle,
                        record: ext.collection && recordId ? { collection: ext.collection, id: recordId } : null,
                    },
                });
                data.isLoading = false;
                break;
            case "idToken":
                requestSessionToken(id);
                break;
            case "navigation.changed": {
                const path = String(payload?.path || "");
                if (!path.startsWith("/") || path.startsWith("//") || path == lastPath) {
                    return;
                }
                // note: the iframe navigations are already part of the joint session history
                lastPath = path;
                history.replaceState(history.state, "", appHash(handle, ext.handle, recordId, path));
                break;
            }
            case "session.ended":
                data.sessionEnded = true;
                break;
            case "toast.show":
                if (payload?.isError) {
                    app.toasts.error(String(payload?.message || ""));
                } else {
                    app.toasts.success(String(payload?.message || ""));
                }
                break;
            case "modal.open":
                openModal(payload);
                break;
            case "modal.close":
                closeModal();
                break;
            case "titleBar.set":
                data.title = String(payload?.title || ext.label);
                app.store.title = data.title;
                break;
            case "resize":
                data.height = Math.max(0, parseInt(payload?.height, 10) || 0);
                break;
        }
    }

    // the frame-src of the loaded dashboard page doesn't have a just installed application yet
    function onCSPViolation(e) {
        if (e.effectiveDirective != "frame-src" || !appOrigin || !e.blockedURI?.startsWith(appOrigin)) {
            return;
        }

        const key = "pbApplicationFrameReload";
        let reloaded = false;
        try {
            reloaded = sessionStorage.getItem(key) == appOrigin;
            sessionStorage.setItem(key, appOrigin);
        } catch {}

        if (reloaded) {
            data.error = "The dashboard security policy doesn't allow this application.";
            data.isLoading = false;
            return;
        }

        window.location.reload();
    }

    async function launch() {
        let result;
        try {
            result = await app.pb.send(
                `/api/applications/installations/${encodeURIComponent(ext.installationId)}/launch`,
                {
                    method: "POST",
                    body: { extension: ext.handle, recordId },
                    requestKey: null,
                },
            );
        } catch (err) {
            app.checkApiError(err);
            data.error = err?.message || "Failed to open the application.";
            data.isLoading = false;
            return;
        }

        const launchURL = new URL(result.url);
        appOrigin = launchURL.origin;

        // defense in depth (also refused by the server): allow-same-origin would escape the sandbox
        if (appOrigin == window.location.origin) {
            data.error = "The application can't be embedded because it has the same origin as the dashboard.";
            data.isLoading = false;
            return;
        }

        // the synced application path (always on the application origin)
        let target = result.url;
        if (lastPath) {
            const candidate = new URL(lastPath, appOrigin);
            if (candidate.origin == appOrigin) {
                target = candidate.href;
            }
        }

        const form = document.createElement("form");
        form.method = "POST";
        form.action = target;
        form.target = FRAME_NAME;
        form.className = "hidden application-extension-launch-form";

        const input = document.createElement("input");
        input.type = "hidden";
        input.name = "launch_token";
        input.value = result.launchToken;
        form.appendChild(input);

        document.body.appendChild(form);
        try {
            form.submit();
        } finally {
            form.remove();
        }
    }

    const page = t.div(
        {
            pbEvent: "pageApplicationFrame",
            className: "page page-application-frame",
            "html-data-application": handle,
            onmount: () => {
                window.addEventListener("message", onMessage);
                document.addEventListener("securitypolicyviolation", onCSPViolation);
                if (ext) {
                    launch();
                }
            },
            onunmount: () => {
                window.removeEventListener("message", onMessage);
                document.removeEventListener("securitypolicyviolation", onCSPViolation);
                closeModal();
                if (active?.page == page) {
                    active = null;
                }
            },
        },
        applicationsSidebar(),
        t.div(
            { className: "page-content full-height" },
            t.header(
                { className: "page-header" },
                t.nav(
                    { className: "breadcrumbs" },
                    t.a({ className: "breadcrumb-item", href: "#/applications" }, "Applications"),
                    t.div(
                        { className: "breadcrumb-item application-frame-title" },
                        ext ? applicationIcon(ext.iconURL) : null,
                        t.span(null, () => data.title),
                    ),
                ),
            ),
            () => {
                if (data.error) {
                    return t.div(
                        { className: "alert danger application-frame-error m-b-sm" },
                        t.div({ className: "content" }, data.error),
                    );
                }
            },
            () => {
                if (data.sessionEnded) {
                    return t.div(
                        { className: "alert warning application-frame-ended m-b-sm" },
                        t.div({ className: "content" }, "Your session with this application has ended."),
                        t.button(
                            { type: "button", className: "btn sm", onclick: () => window.location.reload() },
                            t.span({ className: "txt" }, "Open it again"),
                        ),
                    );
                }
            },
            t.div(
                { className: "application-frame-wrapper", hidden: () => data.sessionEnded },
                () => {
                    if (!ext) {
                        return;
                    }

                    frame = frame || t.iframe({
                        className: "application-frame",
                        name: FRAME_NAME,
                        title: ext.label,
                        "html-sandbox": FRAME_SANDBOX,
                        "html-referrerpolicy": "no-referrer",
                        style: () => (data.height ? `height:${data.height}px` : "height:100%"),
                    });

                    return frame;
                },
            ),
        ),
    );

    return {
        key: routeKey(route),
        page,
        // a hash change that didn't come from the application (e.g. back and forward)
        syncPath(path) {
            if (path == lastPath) {
                return;
            }
            lastPath = path;
            post({ type: "navigation.navigate", payload: { path: path || "/" } });
        },
    };
}
