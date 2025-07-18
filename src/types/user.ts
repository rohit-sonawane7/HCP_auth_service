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
    token: UserToken;
}

export interface UserToken {
    accessToken?: string;
    refreshToken: string;
}


export interface EmailResponse {
    message: string;
    otp: number
}