/**
 * Dashboard login page.
 *
 * The superusers sign in with the hosted login page of the _superusers
 * OAuth2 issuer (pb_dashboard client) so the page only redirects there
 * (or shows the error of a failed authorization response).
 */
export function pageDashboardLogin(route) {
    app.store.title = "Sign in";

    const data = store({
        isRedirecting: false,
        get error() {
            return app.store.authError || "";
        },
    });

    async function signIn() {
        if (data.isRedirecting) {
            return;
        }

        data.isRedirecting = true;
        app.store.authError = "";

        try {
            await app.auth.login();
        } catch (err) {
            console.warn("Failed to start the sign-in:", err);
            app.store.authError = err?.message || "Failed to start the sign-in.";
            data.isRedirecting = false;
        }
    }

    return t.div(
        {
            pbEvent: "pageDashboardLogin",
            className: "wrapper sm m-auto p-b-base dashboard-login",
            onmount: () => {
                // redirect directly to the hosted login page unless there is an error to show
                // (and never while the OAuth2 logout navigation is in progress)
                if (!data.error && !app.auth.isLoggingOut()) {
                    signIn();
                }
            },
        },
        t.header(
            { className: "txt-center m-b-base" },
            t.img({ className: "main-logo", src: () => app.store.mainLogo, ariaHidden: true, alt: "App logo" }),
            t.h5({ className: "m-t-10" }, "Superuser sign in"),
        ),
        () => {
            if (!data.error) {
                return;
            }

            return t.div(
                { className: "alert danger m-b-base" },
                t.div({ className: "content" }, data.error),
            );
        },
        t.button(
            {
                type: "button",
                className: () => `btn lg block ${data.isRedirecting ? "loading" : ""}`,
                disabled: () => data.isRedirecting,
                onclick: signIn,
            },
            t.span({ className: "txt" }, () => (data.isRedirecting ? "Redirecting to sign in..." : "Sign in")),
            t.i({ className: "ri-arrow-right-line", ariaHidden: true }),
        ),
    );
}
