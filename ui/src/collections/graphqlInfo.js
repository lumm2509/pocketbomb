/**
 * Loads the GraphQL schema report of the collections
 * (`{ enabled, collections: [{ collectionId, included, reason, typeName, singularField, pluralField, uniqueArgs, sortFields, fields }] }`).
 *
 * @param  {String} [requestKey]
 * @return {Promise<Object>}
 */
export async function loadGraphQLInfo(requestKey = "graphql_collections_info") {
    return app.pb.send("/api/graphql/collections", { requestKey });
}

/**
 * Returns the GraphQL selection of the collection record scalar fields
 * (the object fields are selected with their primary subfield).
 *
 * @param  {Object} info  A single collection report item.
 * @return {String}
 */
export function graphqlFieldsSelection(info) {
    const selection = [];

    for (const field of info?.fields || []) {
        if (!field.name || field.reason) {
            continue;
        }

        const type = (field.type || "").replace(/[\[\]!]/g, "");
        if (type == "File") {
            selection.push(`${field.name} { filename url }`);
        } else if (type == "GeoPoint") {
            selection.push(`${field.name} { lon lat }`);
        } else if (["ID", "String", "Float", "Boolean", "DateTime", "JSON"].includes(type)) {
            selection.push(field.name);
        } else {
            selection.push(`${field.name} { id }`);
        }
    }

    return selection.join("\n");
}
