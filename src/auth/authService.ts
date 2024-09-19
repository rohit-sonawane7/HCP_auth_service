import 'dotenv/config';
import { InjectRepository } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import { Injectable, UnauthorizedException, InternalServerErrorException, HttpException } from '@nestjs/common';
import { Repository } from 'typeorm';
import { JwtPayload } from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { User } from '../entity/User';
import { NotificationStatus, NotificationType, Otp } from '../entity/Otp';
import { RegisterDto, LoginDto } from '../dto/auth.dto';
import { UserRole, UserToken } from '../types/user';
import { LoggerService } from '../logger/logger';
import { ResetPasswordDto } from '../dto/reset-password.dto';
import { ValidateOtpDto } from '../dto/validate_otp.dto';
import { BullQueueService } from './bullmq.service';
// import { KafkaProducer } from '../kafka/kafka.producer';

@Injectable()
export class AuthService {
    constructor(
        @InjectRepository(User)
        private readonly userRepository: Repository<User>,
        @InjectRepository(Otp)
        private readonly otpRepository: Repository<Otp>,
        private readonly logger: LoggerService,
        private readonly jwtService: JwtService,
        private readonly bullQueueService: BullQueueService,
        // private readonly kafkaProducer: KafkaProducer,
    ) { }

    async registerPatient(registerDto: RegisterDto): Promise<{ message: string }> {
        try {
            const { email, password } = registerDto;
            // const newUser = new User();
            // newUser.email = email;
            // newUser.password = await bcrypt.hash(password, 10);
            // newUser.role = UserRole.USER;
            // newUser.emailVerified = false;
            // newUser.createdAt = new Date();
            // await this.userRepository.save(newUser);
            const newOtp = new Otp();
            // newOtp.email = email;
            // newOtp.type = NotificationType.EMAIL;
            // newOtp.status = NotificationStatus.PENDING;
            newOtp.otp = this.generateOtp();
            // await this.otpRepository.save(newOtp);
            // this.kafkaProducer.sendOtp(email, newOtp.otp);
            return { message: "user register successfully" };
        }
        catch (error) {
            console.error('Error while Registering User:', error);
            if (error instanceof HttpException) {
                throw error;
            }
            throw new InternalServerErrorException('Failed to register user');
        }
    }

    async login(loginDto: LoginDto): Promise<{ id: number, token: UserToken }> {
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
            if (!user.emailVerified) {
                throw new UnauthorizedException('User email is not verified');
            }
            const token = await this.generateJwtToken(String(user.id), true);

            const response = {
                id: user.id,
                token,
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

    async verifyOtp(validateOtpDto: ValidateOtpDto): Promise<boolean> {
        try {
            const { email, otp } = validateOtpDto;
            const existingUser = await this.userRepository.findOneBy({ email });
            if (!existingUser) {
                throw new HttpException('user is not registered', 400);
            }
            const savedOtp = await this.otpRepository.findOneBy({ email });
            if (!savedOtp) return false;
            if (savedOtp.otp === otp && new Date() > savedOtp.expiry_date) {
                await this.userRepository.update({ email }, { emailVerified: true });
                return true;
            } else return false;
        } catch (error) {
            throw new Error('Failed to validate otp');
        }
    }

    private generateOtp(): number {
        return Number(Math.floor(100000 + Math.random() * 900000).toString());
    }

    async handleOtpSent(email: string) {
        await this.bullQueueService.addTask('deleteUnverifiedUser', { email }, 10 * 60 * 1000);
    }

    async deleteUnverifiedUser(email: string) {
        const user = await this.userRepository.findOne({ where: { email } });
        if (user && !user.emailVerified) {
            await this.userRepository.remove(user);
        }
    }
}
