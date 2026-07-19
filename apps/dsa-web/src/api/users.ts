import apiClient from './index';

export type UserRole = 'admin' | 'user';

export type UserRecord = {
  id: number;
  username: string;
  role: UserRole;
  isActive: boolean;
  createdAt?: string;
  updatedAt?: string;
};

export type CreateUserPayload = {
  username: string;
  password: string;
  role?: UserRole;
};

export type UpdateUserPayload = {
  role?: UserRole;
  isActive?: boolean;
};

export const usersApi = {
  async listUsers(): Promise<UserRecord[]> {
    const { data } = await apiClient.get<{ users: UserRecord[] }>('/api/v1/users');
    return data.users ?? [];
  },

  async getCurrentUser(): Promise<UserRecord | null> {
    const { data } = await apiClient.get<UserRecord & { error?: string }>('/api/v1/users/me');
    if (!data || data.error) {
      return null;
    }
    return data;
  },

  async createUser(payload: CreateUserPayload): Promise<UserRecord> {
    const body: { username: string; password: string; role: UserRole } = {
      username: payload.username,
      password: payload.password,
      role: payload.role ?? 'user',
    };
    const { data } = await apiClient.post<UserRecord>('/api/v1/users', body);
    return data;
  },

  async updateUser(userId: number, payload: UpdateUserPayload): Promise<UserRecord> {
    const body: { role?: UserRole; isActive?: boolean } = {};
    if (payload.role !== undefined) {
      body.role = payload.role;
    }
    if (payload.isActive !== undefined) {
      body.isActive = payload.isActive;
    }
    const { data } = await apiClient.patch<UserRecord>(`/api/v1/users/${userId}`, body);
    return data;
  },

  async resetPassword(userId: number, newPassword: string): Promise<void> {
    await apiClient.post(`/api/v1/users/${userId}/reset-password`, {
      newPassword,
    });
  },

  async deleteUser(userId: number): Promise<void> {
    await apiClient.delete(`/api/v1/users/${userId}`);
  },
};
