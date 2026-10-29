import{t as e}from"./clientCredentialsInfo-DaPiTVIv.js";import{n,t as r}from"./fieldsInfo-D_tOPtVP.js";import{fullDummyPayload as i,primitivesDummyPayload as a,replaceDummyPayloadPlaceholder as o}from"./docsCreate-C1NiAk2Y.js";function s(s){let c=app.utils.getApiExampleURL(),l=s.updateRule===null,u=s.type===`auth`?[`id`,`password`,`verified`,`email`,`emailVisibility`]:[`id`],d=s.fields?.filter(e=>!e.hidden&&e.type!=`autodate`&&!u.includes(e.name))||[],f={collectionId:s.id,collectionName:s.name},p=[{title:200,value:JSON.stringify(Object.assign(f,app.utils.getDummyFieldsData(s)),null,2)},{title:400,value:`
                {
                  "status": 400,
                  "message": "Failed to create record.",
                  "data": {
                    "${d.find(e=>!e.primaryKey)?.name||`someField`}": {
                      "code": "validation_required",
                      "message": "Missing required value."
                    }
                  }
                }
            `}];return l&&p.push({title:403,value:`
                {
                  "status": 403,
                  "message": "Only superusers can perform this action.",
                  "data": {}
                }
            `}),p.push({title:404,value:`
            {
              "status": 404,
              "message": "The requested resource wasn't found.",
              "data": {}
            }
        `}),t.div({pbEvent:`apiPreviewUpdate`,className:`content`},t.p(null,`Updates an existing ${s.name} record.`),t.p(null,`Body parameters could be sent as `,t.code(null,`application/json`),` or `,t.code(null,`multipart/form-data`),`.`),t.p(null,`File upload is supported only via `,t.code(null,`multipart/form-data`),`. For more info and examples you could check the detailed `,t.a({href:`https://pocketbase.io/docs/files-handling`,target:`_blank`,rel:`noopener noreferrer`,textContent:`Files upload and handling docs`}),`.`),t.p(null,t.em(null,`Note that in case of a password change all previously issued tokens for the current record will be automatically invalidated and if you want your user to remain signed in you need to reauthenticate manually after the update call.`)),app.components.codeBlockTabs({className:`sdk-examples m-t-sm`,historyKey:`pbLastSDK`,tabs:[{title:`JS SDK`,language:`js`,value:`
import PocketBase from 'pocketbase';

const pb = new PocketBase('${c}');

...

// example update body
const body = ${o(JSON.stringify(i(s,!0),null,2))};

const record = await pb.collection('${s.name}').update('RECORD_ID', body);
`,footnote:t.div({className:`txt-right`},t.a({href:`https://github.com/pocketbase/js-sdk`,target:`_blank`,rel:`noopener noreferrer`,textContent:`JS SDK docs`}))},{title:`Dart SDK`,language:`dart`,value:`
import 'package:pocketbase/pocketbase.dart';

final pb = PocketBase('${c}');

...

// example update body
final body = <String, dynamic>${JSON.stringify(a(s,!0),null,2)};

final record = await pb.collection('${s.name}').update(
  'RECORD_ID',
  body: body,
  files: [],
);
`,footnote:t.div({className:`txt-right`},t.a({href:`https://github.com/pocketbase/dart-sdk`,target:`_blank`,rel:`noopener noreferrer`,textContent:`Dart SDK docs`}))},{title:`curl`,language:`bash`,value:`
                        curl -X PATCH \\
                          -H 'Authorization:TOKEN' \\
                          -H 'Content-Type:application/json' \\
                          -d '{ ... }' \\
                          '${c}/api/collections/${s.name}/records/RECORD_ID'
                    `}]}),t.div({className:`block m-t-base`},t.strong(null,`API details`)),t.div({className:`alert warning api-preview-alert`},t.span({className:`label method`},`PATCH`),t.span({className:`path`},`/api/collections/${s.name}/records/`,t.strong(null,`:id`)),()=>{if(l)return t.small({className:`extra`},`Requires superuser Authorization:TOKEN header`)}),e(),t.table({className:`api-preview-table path-params`},t.thead(null,t.tr(null,t.th({className:`min-width txt-primary`},`Path params`),t.th({className:`min-width`},`Type`),t.th(null,`Description`))),t.tbody(null,t.tr(null,t.td({className:`min-width`},`id`),t.td({className:`min-width`},t.span({className:`label`},`String`)),t.td(null,`ID of the record to update.`)))),t.table({className:`api-preview-table query-params`},t.thead(null,t.tr(null,t.th({className:`min-width txt-primary`},`?query params`),t.th({className:`min-width`},`Type`),t.th(null,`Description`))),t.tbody(null,t.tr(null,t.td({className:`min-width`},`expand`),t.td({className:`min-width`},t.span({className:`label`},`String`)),t.td(null,n())),t.tr(null,t.td({className:`min-width`},`fields`),t.td({className:`min-width`},t.span({className:`label`},`String`)),t.td(null,r())))),t.div({className:`block m-t-base m-b-sm`},t.strong(null,`Example responses`)),app.components.codeBlockTabs({tabs:p}))}export{s as docsUpdate};