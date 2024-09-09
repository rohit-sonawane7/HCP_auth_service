import { Entity, Column, CreateDateColumn, UpdateDateColumn, ObjectIdColumn } from 'typeorm';
import { UserRole } from '../types/user';

@Entity('users')
export class User {
    @ObjectIdColumn()
    id: number;

    @Column()
    first_name: string;

    @Column()
    last_name: string;

    @Column({ unique: true })
    email: string;

    @Column()
    password: string;

    @Column({
        type: 'enum',
        enum: UserRole,
        default: UserRole.USER,
    })
    roles: UserRole;

    @Column()
    emailVerified: boolean;

    @CreateDateColumn({ default: new Date() })
    createdAt: Date;

    @UpdateDateColumn()
    updatedAt: Date;
}
