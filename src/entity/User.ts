import { Entity, Column, CreateDateColumn, UpdateDateColumn, PrimaryGeneratedColumn } from 'typeorm';
import { UserRole } from '../types/user';

@Entity('users')
export class User {
    @PrimaryGeneratedColumn('uuid')
    id: number;

    @Column({ unique: true })
    email: string;

    @Column()
    password: string;

    @Column({
        type: 'enum',
        enum: UserRole,
        default: UserRole.USER,
    })
    role: UserRole;

    @Column({ default: false })
    emailVerified: boolean;

    @CreateDateColumn({ default: new Date() })
    createdAt: Date;

    @UpdateDateColumn()
    updatedAt: Date;
}
