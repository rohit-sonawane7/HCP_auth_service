import { IsString, IsEmail, IsOptional, MinLength, IsArray } from 'class-validator';
import { UserRole } from '../types/user';

export class RegisterDto {

    @IsString()
    first_name: string;

    @IsString()
    last_name: string;

    @IsEmail()
    email: string;

    @IsString()
    @MinLength(6)
    password: string;

    @IsOptional()
    @IsString()
    @IsArray()
    roles?: UserRole;
}

export class LoginDto {
    @IsEmail()
    email: string;

    @IsString()
    @MinLength(6)
    password: string;
}
