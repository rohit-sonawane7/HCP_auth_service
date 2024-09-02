import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../entity/User';
import { RegisterDto, LoginDto } from '../dto/auth.dto';
import { UserRole } from '../types/user';
import { LoggerService } from '../logger/logger';

@Injectable()
export class AuthService {
    constructor(
        @InjectRepository(User)
        private readonly userRepository: Repository<User>,
        private readonly logger: LoggerService
    ) { }

    async register(registerDto: RegisterDto): Promise<void> {
        this.logger.log(`registerDto | ${JSON.stringify(registerDto)}`);
        const { username, email, password, roles } = registerDto;

        const existingUser = await this.userRepository.findOneBy({ email });
        if (existingUser) {
            throw new Error('User already exists');
        }
        this.logger.log(`existingUser | ${JSON.stringify(existingUser)}`);

        const newUser = new User();
        newUser.username = username;
        newUser.email = email;
        newUser.password = await bcrypt.hash(password, 10);;
        newUser.roles = roles || UserRole.USER;
        newUser.createdAt = new Date();
        this.logger.log(`newUser data | ${JSON.stringify(newUser)}`);
        await this.userRepository.save(newUser);
        this.logger.log(`newUser | ${JSON.stringify(newUser)}`);
    }

    async login(loginDto: LoginDto): Promise<string> {
        const { email, password } = loginDto;

        const user = await this.userRepository.findOneBy({ email });
        if (!user) {
            throw new Error('Invalid credentials');
        }

        this.logger.log(`user | ${JSON.stringify(user)}`);

        const isMatch = await bcrypt.compare(password, user.password);
        this.logger.log(`isMatch | ${JSON.stringify(isMatch)}`);

        if (!isMatch) {
            throw new Error('Invalid credentials');
        }
        const payload = {
            user: {
                id: user.id,
            },
        };        

        return jwt.sign(payload, process.env.JWT_SECRET as string, {
            expiresIn: '1h',
        });
    }
}
