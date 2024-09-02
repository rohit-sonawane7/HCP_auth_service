import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthService } from './services/authService';
import { AuthController } from './controllers/authController';
import { User } from './entity/User';
import { LoggerService } from './logger/logger';

@Module({
    imports: [TypeOrmModule.forFeature([User])],
    controllers: [AuthController],
    providers: [AuthService, LoggerService],
})
export class AuthModule { }
