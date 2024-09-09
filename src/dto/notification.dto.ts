export class SendNotificationDto {
    readonly to: string;
    readonly message: string;
    readonly type: 'email' | 'sms';
}