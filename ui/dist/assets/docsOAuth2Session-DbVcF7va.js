import{a as e,c as n,i as r,n as i,o as a,r as o,s,t as c}from"./docsOAuth2Shared-YxT6szAw.js";function l(i){let s=r(i);return t.div({pbEvent:`apiPreviewOAuth2Userinfo`,className:`content`},t.p(null,`Returns the OpenID Connect standard claims of the authenticated record (requires the `,t.code(null,`openid`),` scope; the `,t.code(null,`email`),` and `,t.code(null,`profile`),` scopes add the related claims).`),o([{title:`JS SDK`,language:`js`,value:`
                    const claims = await pb.send('/oauth2/${i.name}/userinfo', {
                        headers: { Authorization: 'Bearer ' + pb.authStore.token },
                    });
                `,footnote:e()},{title:`fetch`,language:`js`,value:`
                    const res = await fetch('${s}/userinfo', {
                        headers: { Authorization: 'Bearer ACCESS_TOKEN' },
                    });
                    const claims = await res.json();
                `}]),c(`GET`,`/oauth2/${i.name}/userinfo`,t.span(null,`Requires`,t.br(),`Authorization: Bearer TOKEN`)),...n([{title:200,value:JSON.stringify({sub:`RECORD_ID`,email:`test@example.com`,email_verified:!0},null,2)},a(401,`invalid_token`,`Invalid or expired access token.`),a(403,`insufficient_scope`,`The access token doesn't have the openid scope.`)]))}function u(l){let u=r(l),d=i(l);return t.div({pbEvent:`apiPreviewOAuth2Revoke`,className:`content`},t.p(null,`Revokes an access or refresh token (RFC 7009). Revoking any of them ends the whole auth session `,`(all its access and refresh tokens stop working immediately).`),o([{title:`fetch`,language:`js`,value:`
                    await fetch('${u}/revoke', {
                        method: 'POST',
                        headers: { 'content-type': 'application/x-www-form-urlencoded' },
                        body: new URLSearchParams({
                            client_id:       '${d}',
                            token:           'REFRESH_TOKEN',
                            token_type_hint: 'refresh_token',
                        }),
                    });

                    pb.authStore.clear();
                `,footnote:e()},{title:`curl`,language:`bash`,value:`
                    curl -X POST '${u}/revoke' \\
                      -d 'client_id=${d}' \\
                      -d 'token=REFRESH_TOKEN'
                `}]),c(`POST`,`/oauth2/${l.name}/revoke`,`application/x-www-form-urlencoded`),s(`Body params`,[[`token`,`String`,`The access or refresh token to revoke.`,!0],[`client_id`,`String`,`The client id (or HTTP Basic client authentication).`,!0],[`token_type_hint`,`String`,t.span(null,t.code(null,`access_token`),` or `,t.code(null,`refresh_token`),`.`)]]),...n([{title:200,value:`(empty; also for invalid or already revoked tokens)`},a(401,`invalid_client`,`Client authentication failed.`)]))}function d(n){let a=r(n),l=i(n);return t.div({pbEvent:`apiPreviewOAuth2Logout`,className:`content`},t.p(null,`OpenID Connect RP-initiated logout. Ends the browser SSO session of the issuer (and its sessions without `,t.code(null,`offline_access`),`) and the session of the `,t.code(null,`id_token_hint`),`. Without a valid `,t.code(null,`id_token_hint`),` the end-user is asked to confirm the logout.`),o([{title:`JS (browser)`,language:`js`,value:`
                    const params = new URLSearchParams({
                        client_id:                '${l}',
                        id_token_hint:            ID_TOKEN,
                        post_logout_redirect_uri: 'https://example.com/',
                        state:                    'STATE',
                    });

                    pb.authStore.clear();

                    window.location.href = '${a}/logout?' + params;
                `,footnote:e()}]),c(`GET`,`/oauth2/${n.name}/logout`,`Browser redirect`),s(`?query params`,[[`id_token_hint`,`String`,`A previously issued id_token (skips the logout confirmation).`],[`post_logout_redirect_uri`,`String`,`One of the client registered post logout redirect URIs.`],[`client_id`,`String`,`The client id (required with post_logout_redirect_uri without id_token_hint).`],[`state`,`String`,`Opaque value returned with the post logout redirect.`]]))}function f(n){let i=app.utils.getApiExampleURL(),a=r(n),s=n.name==`_superusers`,l=[[`Password reset request`,`${a}/password-reset`,`Sends a password reset email (linked from the login page).`],[`Password reset confirm`,`${a}/password-reset/confirm?token=TOKEN`,`The reset password mail link ({ISSUER_URL}/password-reset/confirm?token={TOKEN}).`],[`Email change confirm`,`${a}/email-change/confirm?token=TOKEN`,`The email change mail link ({ISSUER_URL}/email-change/confirm?token={TOKEN}).`]];return s||(l.push([`Verification request`,`${a}/verify-email/request`,`Sends a new verification email (enumeration safe).`],[`Verification confirm`,`${a}/verify-email?token=TOKEN`,`The verification mail link ({ISSUER_URL}/verify-email?token={TOKEN}).`]),n.createRule!==null&&n.passwordAuth?.enabled&&l.push([`Sign up`,`${a}/signup?auth_state=...`,`Linked from the hosted login page (the collection create rule allows guests).`])),t.div({pbEvent:`apiPreviewHostedAccountPages`,className:`content`},t.p(null,`The account flows are hosted pages of the issuer (server-rendered forms with CSRF protection) `,`and the default mail templates link to them. They fire the regular `,t.code(null,`onRecordRequestPasswordResetRequest`),`, `,t.code(null,`onRecordConfirmPasswordResetRequest`),`, `,t.code(null,`onRecordConfirmVerificationRequest`),` and `,t.code(null,`onRecordConfirmEmailChangeRequest`),` hooks.`),t.table({className:`api-preview-table`},t.thead(null,t.tr(null,t.th(null,`Page`),t.th(null,`URL`),t.th(null,`Description`))),t.tbody(null,l.map(([e,n,r])=>t.tr(null,t.td({className:`min-width txt-nowrap`},e),t.td(null,t.code(null,n)),t.td(null,r))))),t.div({className:`m-t-base`},t.strong(null,`Authenticated actor APIs`)),t.p(null,`The email change (and, for the non-staff issuers, the verification email) is requested by the authenticated record:`),o([{title:`JS SDK`,language:`js`,value:`
                    import PocketBase from 'pocketbase';

                    const pb = new PocketBase('${i}');

                    // pb.authStore.save(accessToken, record) - see the Token tab

                    await pb.collection('${n.name}').requestEmailChange('new@example.com');
                    ${s?``:`\n                    await pb.collection('${n.name}').requestVerification(pb.authStore.record.email);`}
                `,footnote:e()},{title:`fetch`,language:`js`,value:`
                    await fetch('${i}/api/collections/${n.name}/request-email-change', {
                        method: 'POST',
                        headers: { 'content-type': 'application/json', Authorization: ACCESS_TOKEN },
                        body: JSON.stringify({ newEmail: 'new@example.com' }),
                    });
                    ${s?``:`
                    await fetch('${i}/api/collections/${n.name}/request-verification', {
                        method: 'POST',
                        headers: { Authorization: ACCESS_TOKEN },
                    });`}
                `}]),c(`POST`,`/api/collections/${n.name}/request-email-change`,t.span(null,`Requires`,t.br(),`Authorization:TOKEN header`)),s?null:c(`POST`,`/api/collections/${n.name}/request-verification`,t.span(null,`Requires`,t.br(),`Authorization:TOKEN header`)))}export{f as docsHostedAccountPages,d as docsOAuth2Logout,u as docsOAuth2Revoke,l as docsOAuth2Userinfo};