import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from './auth.module';
import { User } from './entity/User';
import * as dotenv from 'dotenv';

dotenv.config();

console.log("MONGO_URI");
console.log(process.env.MONGO_URI);

@Module({
    imports: [
        TypeOrmModule.forRoot({
            type: 'mongodb',
            url: process.env.MONGO_URI,
            synchronize: false,
            useUnifiedTopology: true,
            entities: [User],
            migrations: ['src/migration'],
        }),
        TypeOrmModule.forFeature([User]),
        AuthModule,
    ],
})
export class AppModule { }
