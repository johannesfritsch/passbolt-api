export interface User {
  id: string;
  role_id: string;
  username: string;
  active: boolean;
  deleted: boolean;
  created: Date;
  modified: Date;
  groups_users: GroupsUser[];
  profile: Profile;
  gpgkey: Gpgkey | null;
  role: Role;
  last_logged_in: null;
}

interface Gpgkey {
  id: string;
  user_id: string;
  armored_key: string;
  bits: number;
  uid: string;
  key_id: string;
  fingerprint: string;
  type: string;
  expires: null;
  key_created: Date;
  deleted: boolean;
  created: Date;
  modified: Date;
}

interface GroupsUser {
  id: string;
  group_id: string;
  user_id: string;
  is_admin: boolean;
  created: Date;
}

interface Profile {
  id: string;
  user_id: string;
  first_name: string;
  last_name: string;
  created: Date;
  modified: Date;
  avatar: Avatar;
}

interface Avatar {
  url: AvatarUrl;
  id?: string;
  profile_id?: string;
  created?: Date;
  modified?: Date;
}

interface AvatarUrl {
  medium: string;
  small: string;
}

interface Role {
  id: string;
  name: string;
  description: string;
  created: Date;
  modified: Date;
}
