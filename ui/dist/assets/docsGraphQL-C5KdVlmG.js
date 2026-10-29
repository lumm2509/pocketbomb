import{n as e,t as n}from"./index-DeCTAgCv.js";import{t as r}from"./clientCredentialsInfo-DaPiTVIv.js";function i(i){let a=app.utils.getApiExampleURL(),o=store({isLoading:!0,enabled:!0,limits:null,info:null,query:``,isRunning:!1,result:``});s();async function s(){try{let n=await e(`graphql_api_preview`);o.enabled=!!n?.enabled,o.limits=n?.limits||null,o.info=(n?.collections||[]).find(e=>e.collectionId==i.id)||null,o.info?.included&&(o.query=u(o.info,5)),o.isLoading=!1}catch(e){e?.isAbort||(o.isLoading=!1,app.checkApiError(e))}}async function c(){if(!(o.isRunning||!o.query.trim())){o.isRunning=!0;try{let e=await app.pb.send(`/api/graphql`,{method:`POST`,body:{query:o.query},requestKey:`graphql_api_preview_run`});o.result=JSON.stringify(e,null,2)}catch(e){if(e?.isAbort){o.isRunning=!1;return}o.result=JSON.stringify(e?.response||{message:e?.message},null,2)}o.isRunning=!1}}function l(e,n){let r=` `.repeat(n);return e.split(`
`).map(e=>r+e).join(`
`)}function u(e,r=10){let i=(e.sortFields||[]).includes(`created`)?`, sort: "-created"`:``;return[`query {`,`  ${e.pluralField}(first: ${r}${i}) {`,`    totalCount`,`    edges {`,`      cursor`,`      node {`,l(n(e),8),`      }`,`    }`,`    pageInfo {`,`      hasNextPage`,`      endCursor`,`    }`,`  }`,`}`].join(`
`)}function d(e){let r=[`query ($id: ID!) {`,`  ${e.singularField}(id: $id) {`,l(n(e),4),`  }`,`}`],i=e.uniqueArgs?.[0];return i&&r.push(``,`# or by the unique "${i}" field`,`query {`,`  ${e.singularField}(${i}: "VALUE") {`,`    id`,`  }`,`}`),r.join(`
`)}function f(e){let n=`query ($after: String) {
  ${e.pluralField}(first: 20, after: $after) {
    nodes {
      id
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}`;return app.components.codeBlockTabs({className:`sdk-examples m-t-sm`,historyKey:`pbLastGraphQLExample`,tabs:[{title:`fetch (public key)`,language:`js`,value:`
                        // e.g. a storefront with a browser-safe public API key
                        const res = await fetch('${a}/api/graphql', {
                          method: 'POST',
                          headers: {
                            'Content-Type': 'application/json',
                            'X-PB-Public-Key': 'pb_pk_...',
                          },
                          body: JSON.stringify({
                            query: \`${n.replaceAll(`
`,`
                            `)}\`,
                            variables: { after: null },
                          }),
                        });

                        const { data, errors } = await res.json();
                    `},{title:`curl`,language:`bash`,value:`
                        curl -X POST \\
                          -H 'Content-Type: application/json' \\
                          -H 'Authorization: TOKEN' \\
                          -d '{"query":"{ ${e.pluralField}(first: 10) { nodes { id } } }"}' \\
                          '${a}/api/graphql'
                    `}]})}function p(){let e=o.limits||{},n=(e,n,r)=>t.tr(null,t.td({className:`min-width`},e),t.td({className:`min-width`},t.span({className:`label`},String(n??`-`))),t.td(null,r));return t.table({className:`api-preview-table graphql-limits`},t.thead(null,t.tr(null,t.th({className:`min-width txt-primary`},`Limits`),t.th({className:`min-width`},`Value`),t.th(null,`Description`))),t.tbody(null,n(`maxDepth`,e.maxDepth,`Max selection depth (the introspection fields are not counted).`),n(`maxCost`,e.maxCost,`Max static cost: each record costs 1 and the lists multiply their children cost by first/last (default 50) or the relation max select.`),n(`maxPageSize`,e.maxPageSize,`Max first/last value.`),n(`maxQuerySize`,e.maxQuerySize,`Max query size in bytes.`),n(`timeout`,e.timeout?e.timeout+`s`:`-`,`Max execution time.`)))}function m(){let e=o.info;return!e||!e.included?t.div({className:`alert warning graphql-preview-skipped`},`This collection is not exposed in GraphQL`,e?.reason?`: `+e.reason:`.`):[t.p(null,`Read-only GraphQL API (queries only). The ${i.name} records are available as `,t.code(null,e.typeName),` objects with the same access checks as the records API (API rules, API keys, OAuth2 scopes).`),f(e),t.div({className:`block m-t-base`},t.strong(null,`API details`)),t.div({className:`alert info api-preview-alert`},t.span({className:`label method`},`POST`),t.span({className:`path`},`/api/graphql`),t.small({className:`extra`},`or GET /api/graphql?query=...`)),r(),p(),t.div({className:`block m-t-base m-b-sm`},t.strong(null,`List (Relay connection, cursor pagination)`)),app.components.codeBlock({language:`graphql`,value:u(e)}),t.div({className:`block m-t-base m-b-sm`},t.strong(null,`Single record`)),app.components.codeBlock({language:`graphql`,value:d(e)}),t.div({className:`block m-t-base m-b-sm`},t.strong(null,`Try it (as the current dashboard user)`)),t.div({className:`field graphql-preview-query`},t.textarea({rows:10,spellcheck:!1,value:()=>o.query,oninput:e=>o.query=e.target.value})),t.div({className:`flex m-t-sm`},t.button({type:`button`,className:()=>`btn sm graphql-preview-run ${o.isRunning?`loading`:``}`,disabled:()=>o.isRunning,onclick:c},t.i({className:`ri-play-line`,ariaHidden:!0}),t.span({className:`txt`},`Run query`))),t.div({className:`graphql-preview-result-wrapper`},()=>{if(o.result)return app.components.codeBlock({className:`graphql-preview-result m-t-sm`,value:o.result})})]}return t.div({pbEvent:`apiPreviewGraphQL`,className:`content`},()=>{if(o.isLoading)return t.div({className:`block txt-center`},t.span({className:`loader`}));let e=[];return o.enabled||e.push(t.div({className:`alert warning`},`The GraphQL API is disabled (Settings > GraphQL).`)),e.push(...[].concat(m())),e})}export{i as docsGraphQL};