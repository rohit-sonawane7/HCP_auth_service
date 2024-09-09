import { Entity, Column, CreateDateColumn, ObjectIdColumn, } from 'typeorm';

@Entity('otps')
export class Otp {
    @ObjectIdColumn()
    id: number;

    @Column()
    email: string;

    @Column()
    otp: number;

    @CreateDateColumn({ default: new Date(new Date().getTime() + 10 * 60000) })
    expiry_date: Date;

    @CreateDateColumn({ default: new Date() })
    createdAt: Date;
}
