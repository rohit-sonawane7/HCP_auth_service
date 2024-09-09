import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { User } from './entity/User';
import { Otp } from './entity/Otp';
import { LoggerService } from './logger/logger';
import { JwtStrategy } from './utils/jwt/jwtStrategy';
import { AuthService } from './services/authService';
import { AuthController } from './controllers/authController';
import { BullQueueModule } from './bullmq.module';

@Module({
    imports: [
        BullQueueModule,
        ConfigModule.forRoot(),
        TypeOrmModule.forFeature([User, Otp]),
        PassportModule,
        JwtModule.registerAsync({
            imports: [ConfigModule],
            inject: [ConfigService],
            useFactory: async (configService: ConfigService) => ({
                secret: configService.get<string>('JWT_SECRET'),
                signOptions: {
                    expiresIn: configService.get<string>('JWT_EXPIRATION_TIME'),
                },
            }),
        }),
        HttpModule,
    ],
    controllers: [AuthController],
    providers: [AuthService, LoggerService, JwtStrategy],
})
export class AuthModule { }
