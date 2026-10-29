import{c as e,i as n,o as r,r as i,s as a,t as o}from"./docsOAuth2Shared-YxT6szAw.js";function s(s){let c=app.utils.getApiExampleURL(),l=n(s);return t.div({pbEvent:`apiPreviewOAuth2ClientCredentials`,className:`content`},t.p(null,`An installed application authenticates with the OAuth2 client of its installation (`,t.a({href:`#/applications`},`Applications`),`). The client exchanges its `,t.code(null,`client_id`),` and `,t.code(null,`client_secret`),` for a short-lived access token with the `,t.code(null,`client_credentials`),` grant (the only application authentication mechanism).`),t.p(null,`The access token is a regular auth token (`,t.code(null,`Authorization: TOKEN`),` header) of the installation. It expires after `,t.strong(null,(s.authToken?.duration||0)+`s`),` (no refresh token - request a new one) and its access is the installation grant ∩ the token scopes `,`(the granted collection actions bypass the API rules). Rotating the secret or uninstalling the application invalidates the issued tokens.`),i([{title:`fetch`,language:`js`,value:`
                    const res = await fetch('${l}/token', {
                        method: 'POST',
                        headers: {
                            'content-type': 'application/x-www-form-urlencoded',
                            'authorization': 'Basic ' + btoa(CLIENT_ID + ':' + CLIENT_SECRET),
                        },
                        body: new URLSearchParams({
                            grant_type: 'client_credentials',
                            // optional, narrows the installation grant scopes
                            // scope: 'read_posts',
                        }),
                    });

                    const { access_token, expires_in, scope } = await res.json();

                    // use the access token with the regular PocketBase APIs
                    const records = await fetch('${c}/api/collections/posts/records', {
                        headers: { Authorization: access_token },
                    });
                `},{title:`curl`,language:`bash`,value:`
                    curl -X POST '${l}/token' \\
                      -u 'CLIENT_ID:CLIENT_SECRET' \\
                      -d 'grant_type=client_credentials'

                    curl '${c}/api/collections/posts/records' \\
                      -H 'Authorization: Bearer ACCESS_TOKEN'
                `}]),o(`POST`,`/oauth2/${s.name}/token`,t.span(null,`application/x-www-form-urlencoded`,t.br(),`client_secret_basic or client_secret_post`)),a(`Body params`,[[`grant_type`,`String`,t.code(null,`client_credentials`),!0],[`client_id`,`String`,`The installation client id (or HTTP Basic client authentication; never in the URL query).`,!0],[`client_secret`,`String`,`The installation client secret (if not using HTTP Basic).`,!1],[`scope`,`String`,`Optional space-separated subset of the installation grant scopes (read_{collection}, write_{collection}, system:read_{resource}, system:write_{resource}). Default to the full grant.`,!1]]),...e([{title:200,value:JSON.stringify({access_token:`...JWT...`,token_type:`Bearer`,expires_in:s.authToken?.duration||3600,scope:`read_posts write_posts system:read_logs`},null,2)},r(400,`invalid_scope`,`The scope write_posts is not granted to the application installation.`),r(401,`invalid_client`,`Client authentication failed.`)]))}export{s as docsOAuth2ClientCredentials};