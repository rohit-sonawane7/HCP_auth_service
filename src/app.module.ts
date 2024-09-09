import 'dotenv/config';
import { Module } from '@nestjs/common';
import { BullQueueModule } from './bullmq.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from './auth.module';
import { User } from './entity/User';
import { Otp } from './entity/Otp';

@Module({
    imports: [
        TypeOrmModule.forRoot({
            type: 'mongodb',
            url: process.env.MONGO_URI,
            synchronize: true,
            useUnifiedTopology: true,
            entities: [User, Otp],
            migrations: ['src/migration'],
        }),
        TypeOrmModule.forFeature([User, Otp]),
        AuthModule,
        BullQueueModule,
    ],
})

export class AppModule { }
