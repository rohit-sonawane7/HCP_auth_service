import { IsEmail, IsNotEmpty, IsNumber } from 'class-validator';

export class ValidateOtpDto {

    @IsNotEmpty()
    @IsEmail()
    email: string;

    @IsNotEmpty()
    @IsNumber()
    otp: number
}
