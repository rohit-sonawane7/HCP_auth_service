import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, ObjectId, ObjectIdColumn } from 'typeorm';
import { UserRole } from '../types/user';

@Entity('users')
export class User {
    @ObjectIdColumn()
    id: number;

    @Column({ unique: true })
    username: string;

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

    @CreateDateColumn({default: new Date()})
    createdAt: Date;

    @UpdateDateColumn()
    updatedAt: Date;
}
