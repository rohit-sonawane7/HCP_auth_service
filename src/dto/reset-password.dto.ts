// src/auth/dto/reset-password.dto.ts
import { IsEmail, IsNotEmpty, IsString, Length } from 'class-validator';

export class ResetPasswordDto {

    @IsEmail()
    email: string;

    @IsNotEmpty()
    @IsString()
    currentPassword: string;

    @IsNotEmpty()
    @IsString()
    @Length(6, 20)
    newPassword: string;
}
