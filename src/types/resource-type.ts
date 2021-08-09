export interface ResourceType {
  id: string;
  slug: string;
  name: string;
  description: string;
  definition: Definition;
  created: Date;
  modified: Date;
}

interface Definition {
  resource: Resource;
  secret: Secret;
}

interface Resource {
  type: string;
  required: string[];
  properties: ResourceProperties;
}

interface ResourceProperties {
  name: PropertyDefinition;
  username: AnyOfPropertyDefinition;
  uri: AnyOfPropertyDefinition;
  description?: AnyOfPropertyDefinition;
}

interface AnyOfPropertyDefinition {
  anyOf: PropertyDefinition[];
}

interface PropertyDefinition {
  type: 'string' | 'null';
  maxLength?: number;
}

interface Secret {
  type: string;
  maxLength?: number;
  required?: string[];
  properties?: SecretProperties;
}

interface SecretProperties {
  password: PropertyDefinition;
  description: AnyOfPropertyDefinition;
}
