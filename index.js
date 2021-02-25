const { auth, hasRole, hasPermission } = require("keycloak-connect-graphql");
const {
  MapperKind,
  mapSchema,
  getDirectives,
} = require("@graphql-tools/utils");

function parseAndValidateArgsRole(args) {
  const keys = Object.keys(args);

  if (keys.length === 1 && keys[0] === "role") {
    const role = args[keys[0]];
    if (typeof role == "string") {
      return [role];
    }
    if (Array.isArray(role)) {
      return role.map((val) => String(val));
    }
    throw new Error(
      `invalid hasRole args. role must be a String or an Array of Strings`
    );
  }
  throw Error("invalid hasRole args. must contain only a 'role argument");
}

function parseAndValidateArgsPermission(args) {
  const keys = Object.keys(args);

  if (keys.length === 1 && keys[0] === "resources") {
    const resources = args[keys[0]];
    if (typeof resources == "string") {
      return [resources];
    }
    if (Array.isArray(resources)) {
      return resources.map((val) => String(val));
    }
    throw new Error(
      `invalid hasPermission args. resources must be a String or an Array of Strings`
    );
  }
  throw Error(
    "invalid hasPermission args. must contain only a 'resources argument"
  );
}

function authDir(schema) {
  return mapSchema(schema, {
    [MapperKind.OBJECT_FIELD]: (fieldConfig) => {
      const directives = getDirectives(schema, fieldConfig);
      if (directives.auth) {
        const { resolve } = fieldConfig;
        fieldConfig.resolve = auth(resolve);
        return fieldConfig;
      }
    },
  });
}

function hasRoleDir(schema) {
  return mapSchema(schema, {
    [MapperKind.OBJECT_FIELD]: (fieldConfig) => {
      const directives = getDirectives(schema, fieldConfig);
      if (directives.hasRole) {
        const { resolve } = fieldConfig;
        const roles = parseAndValidateArgsRole(directives.hasRole);
        fieldConfig.resolve = hasRole(roles)(resolve);
        return fieldConfig;
      }
    },
  });
}

function hasPermissionDir(schema) {
  return mapSchema(schema, {
    [MapperKind.OBJECT_FIELD]: (fieldConfig) => {
      const directives = getDirectives(schema, fieldConfig);
      if (directives.hasPermission) {
        const { resolve } = fieldConfig;
        const resources = parseAndValidateArgsPermission(
          directives.hasPermission
        );
        fieldConfig.resolve = hasPermission(resources)(resolve);
        return fieldConfig;
      }
    },
  });
}

module.exports = {
  authDir,
  hasRoleDir,
  hasPermissionDir,
};
