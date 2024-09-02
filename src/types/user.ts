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