export enum UserRole {
    ADMIN = 'admin',
    USER = 'user',
    MODERATOR = 'moderator',
}

export interface RegisterRequest {
    username: string;
    email: string;
    password: string;
    roles?: UserRole;
}

export interface LoginResponse {
    id: number;
    name: string;
    token: UserToken;
}

export interface UserToken {
    accessToken?: string;
    refreshToken: string;
}
