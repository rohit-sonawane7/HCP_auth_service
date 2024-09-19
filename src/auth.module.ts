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
import { AuthController } from './auth/auth.controller';
import { BullQueueModule } from './bullmq.module';
import { ClientKafka } from '@nestjs/microservices';

@Module({
    imports: [
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
    ],
    controllers: [AuthController],
    providers: [AuthService, LoggerService, JwtStrategy],
})
export class AuthModule { }
