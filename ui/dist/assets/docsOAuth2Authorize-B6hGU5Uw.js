import{a as e,i as n,n as r,r as i,s as a,t as o}from"./docsOAuth2Shared-YxT6szAw.js";function s(s){let c=n(s),l=r(s),u=[s.passwordAuth?.enabled?`password`:``,s.otp?.enabled?`one-time code`:``,s.oauth2?.enabled&&s.name!=`_superusers`?`OAuth2 providers`:``].filter(Boolean);return t.div({pbEvent:`apiPreviewOAuth2Authorize`,className:`content`},t.p(null,`Every auth collection is an OAuth2 / OpenID Connect issuer and the `,t.strong(null,`only way to authenticate`),` a `,t.code(null,s.name),` record is the Authorization Code flow with PKCE using the issuer hosted login pages.`),t.p(null,`Redirect the browser to the authorization endpoint. After the end-user signs in on the hosted pages (`,u.length?u.join(`, `):`no sign-in methods are enabled`,s.mfa?.enabled?`; MFA enabled`:``,`) the browser is redirected back to your `,t.code(null,`redirect_uri`),` with `,t.code(null,`code`),`, `,t.code(null,`state`),` and `,t.code(null,`iss`),` query parameters that you exchange for tokens (see the Token tab).`),i([{title:`JS (browser)`,language:`js`,value:`
                    // generate the PKCE verifier and challenge (S256)
                    const random = (n) => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(n))))
                        .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');

                    const verifier = random(48);
                    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
                    const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
                        .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');

                    const state = random(24);
                    sessionStorage.setItem('pb_oauth2', JSON.stringify({ verifier, state }));

                    const params = new URLSearchParams({
                        client_id:             '${l}',
                        redirect_uri:          'https://example.com/callback',
                        response_type:         'code',
                        scope:                 'openid email offline_access',
                        state:                 state,
                        nonce:                 random(24),
                        code_challenge:        challenge,
                        code_challenge_method: 'S256',
                    });

                    window.location.href = '${c}/authorize?' + params;
                `,footnote:e()},{title:`URL`,language:`bash`,value:`
                    ${c}/authorize
                      ?client_id=${l}
                      &redirect_uri=https%3A%2F%2Fexample.com%2Fcallback
                      &response_type=code
                      &scope=openid%20email%20offline_access
                      &state=STATE
                      &nonce=NONCE
                      &code_challenge=S256_CHALLENGE
                      &code_challenge_method=S256
                `}]),o(`GET`,`/oauth2/${s.name}/authorize`,`Browser redirect`),a(`?query params`,[[`client_id`,`String`,`The registered OAuth2 client id (Settings > OAuth2 clients).`,!0],[`redirect_uri`,`String`,`Exact match of one of the client registered redirect URIs.`,!0],[`response_type`,`String`,t.span(null,`Must be `,t.code(null,`code`),`.`),!0],[`scope`,`String`,t.span(null,`Space separated scopes allowed for the client (deny by default). The third-party clients need the collection scopes (`,t.code(null,`read_{collection}`),` for list/view, `,t.code(null,`write_{collection}`),` for create/update/delete) — their access is the user roles permissions ∩ the granted collection scopes. The system resources scopes have their own `,t.code(null,`system:read_{resource}`),`/`,t.code(null,`system:write_{resource}`),` namespace (reserved, not grantable to the OAuth2 clients) so a `,t.code(null,`read_{collection}`),` scope never maps to a system resource.`),!0],[`code_challenge`,`String`,`PKCE S256 code challenge (required for all clients).`,!0],[`code_challenge_method`,`String`,t.span(null,`Must be `,t.code(null,`S256`),`.`),!0],[`state`,`String`,`Opaque value returned unchanged with the redirect (CSRF protection).`],[`nonce`,`String`,`Value returned in the id_token nonce claim.`],[`prompt`,`String`,t.span(null,t.code(null,`none`),` (no UI; reuse the SSO session or return login_required), `,t.code(null,`login`),` (force re-authentication), `,t.code(null,`consent`),` or `,t.code(null,`create`),` (open the hosted sign up page; only if the collection allows the sign up).`)],[`max_age`,`Number`,`Max allowed seconds since the last interactive authentication.`],[`login_hint`,`String`,`Prefilled identity on the hosted login page.`]]),t.div({className:`m-t-base m-b-sm`},t.strong(null,`Redirect responses`)),app.components.codeBlockTabs({tabs:[{title:`Success`,language:`bash`,value:`https://example.com/callback?code=CODE&state=STATE&iss=`+encodeURIComponent(c)},{title:`Error`,language:`bash`,value:`https://example.com/callback?error=access_denied&error_description=...&state=STATE&iss=`+encodeURIComponent(c)}]}))}export{s as docsOAuth2Authorize};