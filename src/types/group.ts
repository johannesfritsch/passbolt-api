export interface Group {
  created_by: string;
  modified_by: string;
  deleted: boolean;
  name: string;
  groups_users: GroupsUser[];
  created: Date;
  modified: Date;
  id: string;
}

interface GroupsUser {
  user_id: string;
  is_admin: boolean;
  group_id: string;
  created: Date;
  id: string;
}
