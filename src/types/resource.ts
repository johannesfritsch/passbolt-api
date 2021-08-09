export interface Resource {
  id: string;
  name: string;
  username: string | null;
  uri: string | null;
  description: string | null;
  deleted: boolean;
  created: Date;
  modified: Date;
  created_by: string;
  modified_by: string;
  resource_type_id: string;
  favorite: null;
  modifier: User;
  creator: User;
  secrets: Secret[];
  permission: Permission;
}

interface User {
  id: string;
  role_id: string;
  username: string;
  active: boolean;
  deleted: boolean;
  created: Date;
  modified: Date;
  last_logged_in: null;
}

interface Permission {
  id: string;
  aco: string;
  aco_foreign_key: string;
  aro: string;
  aro_foreign_key: string;
  type: number;
  created: Date;
  modified: Date;
}

interface Secret {
  id: string;
  user_id: string;
  resource_id: string;
  data: string;
  created: Date;
  modified: Date;
}
