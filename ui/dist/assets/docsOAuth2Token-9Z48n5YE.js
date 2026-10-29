import{a as e,c as n,i as r,n as i,o as a,r as o,s,t as c}from"./docsOAuth2Shared-YxT6szAw.js";function l(l){let u=app.utils.getApiExampleURL(),d=r(l),f=i(l);return t.div({pbEvent:`apiPreviewOAuth2Token`,className:`content`},t.p(null,`The token endpoint is the only endpoint that issues auth tokens. Exchange the authorization code (`,t.code(null,`authorization_code`),` grant) or a refresh token (`,t.code(null,`refresh_token`),` grant) for a new access token.`),t.p(null,`The access token is a regular `,t.code(null,l.name),` auth token (`,t.code(null,`Authorization: TOKEN`),` header) backed by an auth session. It expires after `,t.strong(null,(l.authToken?.duration||0)+`s`),` (the collection auth token duration) and it is renewed with the rotating refresh token `,`(the refresh tokens of the sessions without `,t.code(null,`offline_access`),` end together with the browser SSO session).`),o([{title:`JS SDK`,language:`js`,value:`
                    import PocketBase, { getTokenPayload } from 'pocketbase';

                    const pb = new PocketBase('${u}');

                    // on the redirect_uri page
                    const query = new URLSearchParams(window.location.search);
                    const flow = JSON.parse(sessionStorage.getItem('pb_oauth2'));
                    if (query.get('state') !== flow.state) {
                        throw new Error('invalid state');
                    }

                    const res = await fetch('${d}/token', {
                        method: 'POST',
                        headers: { 'content-type': 'application/x-www-form-urlencoded' },
                        body: new URLSearchParams({
                            grant_type:    'authorization_code',
                            client_id:     '${f}',
                            code:          query.get('code'),
                            redirect_uri:  'https://example.com/callback',
                            code_verifier: flow.verifier,
                        }),
                    });
                    const tokens = await res.json();

                    // load the record and save the issued token in the SDK auth store
                    const record = await pb.collection('${l.name}').getOne(
                        getTokenPayload(tokens.access_token).id,
                        { headers: { Authorization: tokens.access_token } },
                    );
                    pb.authStore.save(tokens.access_token, record);

                    // later, before the access token expires
                    const refreshed = await (await fetch('${d}/token', {
                        method: 'POST',
                        headers: { 'content-type': 'application/x-www-form-urlencoded' },
                        body: new URLSearchParams({
                            grant_type:    'refresh_token',
                            client_id:     '${f}',
                            refresh_token: tokens.refresh_token,
                        }),
                    })).json();
                    pb.authStore.save(refreshed.access_token, pb.authStore.record);
                `,footnote:e()},{title:`fetch`,language:`js`,value:`
                    const res = await fetch('${d}/token', {
                        method: 'POST',
                        headers: { 'content-type': 'application/x-www-form-urlencoded' },
                        body: new URLSearchParams({
                            grant_type:    'authorization_code',
                            client_id:     '${f}',
                            code:          'CODE',
                            redirect_uri:  'https://example.com/callback',
                            code_verifier: 'PKCE_VERIFIER',
                        }),
                    });

                    const { access_token, refresh_token, id_token, expires_in } = await res.json();

                    // use the access token with the regular PocketBase APIs
                    const records = await fetch('${u}/api/collections/posts/records', {
                        headers: { Authorization: access_token },
                    });
                `},{title:`curl`,language:`bash`,value:`
                    # authorization code exchange
                    curl -X POST '${d}/token' \\
                      -d 'grant_type=authorization_code' \\
                      -d 'client_id=${f}' \\
                      -d 'code=CODE' \\
                      -d 'redirect_uri=https://example.com/callback' \\
                      -d 'code_verifier=PKCE_VERIFIER'

                    # refresh (the refresh token is rotated on each use)
                    curl -X POST '${d}/token' \\
                      -d 'grant_type=refresh_token' \\
                      -d 'client_id=${f}' \\
                      -d 'refresh_token=REFRESH_TOKEN'
                `}]),c(`POST`,`/oauth2/${l.name}/token`,t.span(null,`application/x-www-form-urlencoded`,t.br(),`confidential clients: client_secret_basic/post`)),s(`Body params`,[[`grant_type`,`String`,t.span(null,t.code(null,`authorization_code`),` or `,t.code(null,`refresh_token`),`.`),!0],[`client_id`,`String`,`The client id (or HTTP Basic client authentication).`,!0],[`code`,`String`,`The authorization code (authorization_code grant; single use).`,!1],[`redirect_uri`,`String`,`The same redirect_uri as in the authorization request (authorization_code grant).`,!1],[`code_verifier`,`String`,`The PKCE code verifier (authorization_code grant).`,!1],[`refresh_token`,`String`,`The current refresh token (refresh_token grant; reuse ends the session).`,!1],[`client_secret`,`String`,`The secret of confidential clients (if not using HTTP Basic).`,!1]]),...n([{title:200,value:JSON.stringify({access_token:`...JWT...`,token_type:`Bearer`,expires_in:l.authToken?.duration||3600,scope:`openid email offline_access`,id_token:`...JWT...`,refresh_token:`...`},null,2)},a(400,`invalid_grant`,`Invalid or expired authorization code.`),a(401,`invalid_client`,`Client authentication failed.`)]))}export{l as docsOAuth2Token};