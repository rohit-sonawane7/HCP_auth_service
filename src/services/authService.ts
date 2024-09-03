import 'dotenv/config';
import bcrypt from 'bcryptjs';
import { JwtPayload } from 'jsonwebtoken';
import { Repository } from 'typeorm';
import {
    Injectable,
    UnauthorizedException,
    InternalServerErrorException,
    HttpException,
} from '@nestjs/common';
import { User } from '../entity/User';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { RegisterDto, LoginDto } from '../dto/auth.dto';
import { UserRole, UserToken } from '../types/user';
import { LoggerService } from '../logger/logger';
import { ResetPasswordDto } from '../dto/reset-password.dto';

@Injectable()
export class AuthService {
    constructor(
        @InjectRepository(User)
        private readonly userRepository: Repository<User>,
        private readonly logger: LoggerService,
        private readonly jwtService: JwtService,
    ) { }

    async register(registerDto: RegisterDto): Promise<void> {
        try {
            const { username, email, password, roles } = registerDto;
            const existingUser = await this.userRepository.findOneBy({ email });
            if (existingUser) {
                throw new HttpException('User already exists', 400);
            }
            const newUser = new User();
            newUser.username = username;
            newUser.email = email;
            newUser.password = await bcrypt.hash(password, 10);
            newUser.roles = roles || UserRole.USER;
            newUser.createdAt = new Date();
            await this.userRepository.save(newUser);
        }
        catch (error) {
            console.error('Error while Registering User:', error);
            if (error instanceof HttpException) {
                throw error;
            }
            throw new InternalServerErrorException('Failed to register user');
        }
    }

    async login(loginDto: LoginDto): Promise<{ id: number, name: string, token: UserToken }> {
        try {
            const { email, password } = loginDto;
            const user = await this.userRepository.findOneBy({ email });
            if (!user) {
                throw new UnauthorizedException('Invalid credentials');
            }
            this.logger.log(`user | ${JSON.stringify(user)}`);
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                throw new UnauthorizedException('Invalid credentials');
            }
            const token = await this.generateJwtToken(String(user.id), true);

            const response = {
                id: user.id,
                token,
                name: user.username
            }

            return response;
        } catch (error) {
            console.error('Error creating user:', error);
            if (error instanceof HttpException) {
                throw error;
            }
            throw new InternalServerErrorException('Failed to login');
        }
    }

    async resetPassword(resetPasswordDto: ResetPasswordDto): Promise<{ message: string }> {
        try {
            const { email, currentPassword, newPassword } = resetPasswordDto;
            const user = await this.userRepository.findOneBy({ email });
            if (!user) {
                throw new UnauthorizedException('User not found');
            }
            const isPasswordMatch = await bcrypt.compare(currentPassword, user.password);
            if (!isPasswordMatch) {
                throw new UnauthorizedException('Current password is incorrect');
            }
            const isNewPasswordSame = await bcrypt.compare(newPassword, user.password);
            if (isNewPasswordSame) {
                throw new UnauthorizedException('New password must be different from the current password');
            }
            const hashedNewPassword = await bcrypt.hash(newPassword, 10);
            user.password = hashedNewPassword;
            await this.userRepository.save(user);
            return {
                message: "password reset successfully"
            }
        } catch (error) {
            console.error('Error reseting password:', error);
            if (error instanceof HttpException) {
                throw error;
            }
            throw new InternalServerErrorException('Failed to reset password');
        }
    }

    async refreshJwtToken(refreshToken: string): Promise<UserToken> {
        try {
            const payload = await this.verifyToken(refreshToken);
            const newToken = await this.generateJwtToken(payload.userId);
            return newToken;
        } catch (error) {
            console.error('Error during token refresh:', error);
            throw new UnauthorizedException('Failed to refresh token');
        }
    }

    async generateJwtToken(userId: string, both?: boolean): Promise<UserToken> {
        try {
            const payload: JwtPayload = { userId };
            const tokens: UserToken = {
                accessToken: '',
                refreshToken: '',
            }
            tokens['refreshToken'] = this.jwtService.sign(payload, { expiresIn: '7d' });
            if (both) {
                tokens['accessToken'] = this.jwtService.sign(payload);
            } else {
                delete tokens.accessToken;
            }
            return tokens;
        } catch (error) {
            throw new InternalServerErrorException(`Failed to generate ${!both ? `refresh token` : `token`}`);
        }
    }

    async verifyToken(token: string): Promise<any> {
        try {
            return this.jwtService.verify(token);
        } catch (error) {
            throw new UnauthorizedException('Invalid or expired token');
        }
    }
}
