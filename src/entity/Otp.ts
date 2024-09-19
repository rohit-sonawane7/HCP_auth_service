import { Entity, Column, CreateDateColumn, PrimaryGeneratedColumn, } from 'typeorm';

export enum NotificationType {
    EMAIL = 'EMAIL',
    SMS = 'SMS',
}

export enum NotificationStatus {
    PENDING = 'PENDING',
    SENT = 'SENT',
    FAILED = 'FAILED',
}


@Entity('otps')
export class Otp {
    @PrimaryGeneratedColumn('uuid')
    id: number;

    @Column({ type: 'enum', enum: NotificationType })
    type: NotificationType;

    @Column({ type: 'enum', enum: NotificationStatus, default: NotificationStatus.PENDING })
    status: NotificationStatus;

    @Column({ nullable: true })
    email: string;

    @Column({ nullable: true })
    phone_number: string;

    @Column()
    otp: number;

    @CreateDateColumn({ default: new Date(new Date().getTime() + 10 * 60000) })
    expiry_date: Date;

    @CreateDateColumn({ default: new Date() })
    createdAt: Date;
}
