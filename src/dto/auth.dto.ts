import { IsString, IsEmail, IsOptional, MinLength, IsArray } from 'class-validator';
import { UserRole } from '../types/user';

export class RegisterDto {

    @IsEmail()
    email: string;

    @IsString()
    @MinLength(6)
    password: string;
}

export class LoginDto {
    @IsEmail()
    email: string;

    @IsString()
    @MinLength(6)
    password: string;
}
